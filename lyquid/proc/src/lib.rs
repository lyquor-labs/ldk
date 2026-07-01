#![allow(dead_code)]

//! Compile-time expansion for Lyquid state, method, and call syntax.
//!
//! `lyquid-proc` translates the source-level Lyquid DSL into the guest ABI exported by `lyquid`.
//! It validates method signatures, prefixes network, instance, Ethereum, oracle, and UPC entry
//! point names, encodes method metadata into custom sections, builds context wrappers, and emits
//! state-variable initialization glue. Runtime crates consume the generated names and metadata
//! after `lyquor-wasm` extracts them from the compiled module.

use proc_macro2::*;

use std::collections::HashMap;

fn token_is_group(tt: TokenTree) -> Option<Group> {
    match tt {
        TokenTree::Group(grp) => Some(grp),
        _ => None,
    }
}

fn token_is_literal(tt: TokenTree) -> Option<Literal> {
    match tt {
        TokenTree::Literal(l) => Some(l),
        _ => None,
    }
}

fn token_is_ident(tt: TokenTree) -> Option<Ident> {
    match tt {
        TokenTree::Ident(id) => Some(id),
        _ => None,
    }
}

fn next_token_is_group(iter: &mut token_stream::IntoIter) -> Option<Group> {
    iter.next().and_then(token_is_group)
}

fn next_token_is_ident(iter: &mut token_stream::IntoIter) -> Option<Ident> {
    iter.next().and_then(token_is_ident)
}

fn next_token_is_literal(iter: &mut token_stream::IntoIter) -> Option<Literal> {
    iter.next().and_then(token_is_literal)
}

fn add_prefix(attr: TokenStream, ident: Ident) -> Ident {
    let mut tokens = Vec::new();
    for t in attr {
        let l = match t {
            TokenTree::Ident(id) => id.to_string(),
            TokenTree::Literal(l) => {
                let s: syn::LitStr =
                    syn::parse(TokenStream::from(TokenTree::from(l)).into()).expect("invalid prefix literal");
                s.value()
            }
            TokenTree::Punct(_) => continue,
            TokenTree::Group(g) => {
                // Handle grouped tokens like ($($group)::*) - stringify the contents
                let mut group_result = String::new();
                for token in g.stream() {
                    match token {
                        TokenTree::Ident(id) => group_result.push_str(&id.to_string()),
                        TokenTree::Punct(p) => group_result.push(p.as_char()),
                        TokenTree::Literal(l) => group_result.push_str(&l.to_string()),
                        TokenTree::Group(_) => panic!("nested groups not supported"),
                    }
                }
                group_result
            }
        };
        tokens.push(l);
    }
    syn::Ident::new(
        &lyquor_primitives::encode_method_name(
            &tokens[0..tokens.len() - 1].join("_"),
            &tokens[tokens.len() - 1],
            &ident.to_string(),
        ),
        Span::call_site(),
    )
}

struct ParsedFunctionCommon {
    ctx_ident: syn::Ident,
    ctx_mut: bool,
    params: Vec<(syn::Ident, syn::Type)>,
    attrs: Vec<syn::Attribute>,
    fn_name: syn::Ident,
    body: Box<syn::Block>,
    output: syn::ReturnType,
}

struct ParsedFunction {
    ctx_ident: syn::Ident,
    ctx_mut: bool,
    params: Vec<(syn::Ident, syn::Type)>,
    ret_inner: syn::Type,
    attrs: Vec<syn::Attribute>,
    fn_name: syn::Ident,
    body: Box<syn::Block>,
}

struct ParsedConstructor {
    ctx_ident: syn::Ident,
    ctx_mut: bool,
    params: Vec<(syn::Ident, syn::Type)>,
    attrs: Vec<syn::Attribute>,
    fn_name: syn::Ident,
    body: Box<syn::Block>,
}

struct HttpExportAttr {
    method: String,
    path_prefix: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EthExportGuard {
    None,
    Creator,
}

struct EthExportAttr {
    guard: EthExportGuard,
}

enum ExportKind {
    Ethereum(EthExportAttr),
    Http(HttpExportAttr),
}

struct MethodAttr {
    group: Option<syn::Path>,
    export: Option<ExportKind>,
}

fn parse_function_common(func: syn::ItemFn) -> syn::Result<ParsedFunctionCommon> {
    let syn::ItemFn { attrs, sig, block, .. } = func;
    if sig.asyncness.is_some() {
        return Err(syn::Error::new_spanned(
            sig.fn_token,
            "async functions are not supported",
        ));
    }
    if sig.constness.is_some() {
        return Err(syn::Error::new_spanned(
            sig.fn_token,
            "const functions are not supported",
        ));
    }
    if sig.abi.is_some() {
        return Err(syn::Error::new_spanned(
            sig.fn_token,
            "extern functions are not supported",
        ));
    }
    if sig.variadic.is_some() {
        return Err(syn::Error::new_spanned(
            sig.fn_token,
            "variadic functions are not supported",
        ));
    }
    if !sig.generics.params.is_empty() || sig.generics.where_clause.is_some() {
        return Err(syn::Error::new_spanned(
            sig.generics,
            "generic functions are not supported",
        ));
    }

    let mut inputs = sig.inputs.iter();
    let ctx_arg = inputs
        .next()
        .ok_or_else(|| syn::Error::new_spanned(sig.fn_token, "expected a context parameter like `ctx: &mut _`"))?;

    let (ctx_ident, ctx_mut) = match ctx_arg {
        syn::FnArg::Receiver(receiver) => {
            return Err(syn::Error::new_spanned(
                receiver,
                "method receivers are not supported; use `ctx: &mut _` or `ctx: &_`",
            ));
        }
        syn::FnArg::Typed(pat_type) => {
            let ctx_ident = match &*pat_type.pat {
                syn::Pat::Ident(ident) => ident.ident.clone(),
                _ => {
                    return Err(syn::Error::new_spanned(
                        &pat_type.pat,
                        "context parameter must be an identifier like `ctx`",
                    ));
                }
            };
            if ctx_ident == "_" {
                return Err(syn::Error::new_spanned(
                    &pat_type.pat,
                    "context parameter must be a named identifier",
                ));
            }
            let syn::Type::Reference(ctx_ref) = &*pat_type.ty else {
                return Err(syn::Error::new_spanned(
                    &pat_type.ty,
                    "context parameter must be a reference: `ctx: &mut _` or `ctx: &_`",
                ));
            };
            (ctx_ident, ctx_ref.mutability.is_some())
        }
    };

    let mut params = Vec::new();
    for arg in inputs {
        let pat_type = match arg {
            syn::FnArg::Typed(pat_type) => pat_type,
            syn::FnArg::Receiver(receiver) => {
                return Err(syn::Error::new_spanned(
                    receiver,
                    "method receivers are not supported; use `ctx: &mut _` or `ctx: &_`",
                ));
            }
        };
        let ident = match &*pat_type.pat {
            syn::Pat::Ident(ident) => ident.ident.clone(),
            _ => {
                return Err(syn::Error::new_spanned(
                    &pat_type.pat,
                    "parameter must be an identifier like `name: Type`",
                ));
            }
        };
        if ident == "_" {
            return Err(syn::Error::new_spanned(
                &pat_type.pat,
                "parameters must be named identifiers",
            ));
        }
        params.push((ident, (*pat_type.ty).clone()));
    }

    Ok(ParsedFunctionCommon {
        ctx_ident,
        ctx_mut,
        params,
        attrs,
        fn_name: sig.ident,
        body: block,
        output: sig.output,
    })
}

fn parse_function_signature(func: syn::ItemFn) -> syn::Result<ParsedFunction> {
    let ParsedFunctionCommon {
        ctx_ident,
        ctx_mut,
        params,
        attrs,
        fn_name,
        body,
        output,
    } = parse_function_common(func)?;

    let ret_inner = match &output {
        syn::ReturnType::Type(_, ty) => {
            let syn::Type::Path(ty_path) = &**ty else {
                return Err(syn::Error::new_spanned(&output, "return type must be LyquidResult<T>"));
            };
            let segment = ty_path
                .path
                .segments
                .last()
                .ok_or_else(|| syn::Error::new_spanned(&output, "return type must be LyquidResult<T>"))?;
            if segment.ident != "LyquidResult" {
                return Err(syn::Error::new_spanned(segment, "return type must be LyquidResult<T>"));
            }
            match &segment.arguments {
                syn::PathArguments::AngleBracketed(args) => {
                    let mut iter = args.args.iter();
                    let inner = match iter.next() {
                        Some(syn::GenericArgument::Type(inner)) => inner.clone(),
                        _ => {
                            return Err(syn::Error::new_spanned(
                                &segment.arguments,
                                "return type must be LyquidResult<T>",
                            ));
                        }
                    };
                    if iter.next().is_some() {
                        return Err(syn::Error::new_spanned(
                            &segment.arguments,
                            "return type must be LyquidResult<T>",
                        ));
                    }
                    inner
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        &segment.arguments,
                        "return type must be LyquidResult<T>",
                    ));
                }
            }
        }
        syn::ReturnType::Default => {
            return Err(syn::Error::new_spanned(&output, "return type must be LyquidResult<T>"));
        }
    };

    Ok(ParsedFunction {
        ctx_ident,
        ctx_mut,
        params,
        ret_inner,
        attrs,
        fn_name,
        body,
    })
}

fn parse_constructor_signature(func: syn::ItemFn) -> syn::Result<ParsedConstructor> {
    let ParsedFunctionCommon {
        ctx_ident,
        ctx_mut,
        params,
        attrs,
        fn_name,
        body,
        output,
    } = parse_function_common(func)?;

    if fn_name != "constructor" {
        return Err(syn::Error::new_spanned(
            fn_name,
            "constructor function must be named `constructor`",
        ));
    }

    if !matches!(output, syn::ReturnType::Default) {
        return Err(syn::Error::new_spanned(
            output,
            "constructor must not specify a return type",
        ));
    }

    Ok(ParsedConstructor {
        ctx_ident,
        ctx_mut,
        params,
        attrs,
        fn_name,
        body,
    })
}

// Expands #[lyquid::method::network], with a constructor special-case.
fn expand_network_function(attr: TokenStream, func: syn::ItemFn) -> syn::Result<TokenStream> {
    if func.sig.ident == "constructor" {
        let parsed_attr = parse_method_attr(attr, "lyquid::method::network")?;
        if parsed_attr.group.is_some() {
            return Err(syn::Error::new_spanned(
                func.sig.ident,
                "constructor does not accept group arguments",
            ));
        }
        if matches!(parsed_attr.export.as_ref(), Some(ExportKind::Http(_))) {
            return Err(syn::Error::new_spanned(
                func.sig.ident,
                "`export = http` is only supported on #[lyquid::method::instance]",
            ));
        }
        let parsed = parse_constructor_signature(func)?;
        return expand_constructor(parsed, parsed_attr.export);
    }

    // Parse optional group metadata and lower to __lyquid_categorize_methods.
    let MethodAttr {
        group: group_path,
        export,
    } = parse_method_attr(attr, "lyquid::method::network")?;
    if matches!(export.as_ref(), Some(ExportKind::Http(_))) {
        return Err(syn::Error::new_spanned(
            func.sig.ident,
            "`export = http` is only supported on #[lyquid::method::instance]",
        ));
    }
    let parsed = parse_function_signature(func)?;
    let ctx_ident = parsed.ctx_ident;
    let ctx_mut = parsed.ctx_mut;
    let params = parsed.params;
    let ret_inner = parsed.ret_inner;
    let attrs = parsed.attrs;
    let fn_name = parsed.fn_name;
    let body = parsed.body;

    let group_tokens = match group_path.as_ref() {
        Some(path) => quote::quote!(#path),
        None => quote::quote!(main),
    };
    let ctx_pattern = if ctx_mut {
        quote::quote! { &mut #ctx_ident }
    } else {
        quote::quote! { & #ctx_ident }
    };
    let params_ts = params.iter().map(|(ident, ty)| quote::quote! { #ident: #ty });
    let export_flag = if matches!(export.as_ref(), Some(ExportKind::Ethereum(_))) {
        quote::quote! { true }
    } else {
        quote::quote! { false }
    };

    let export_tokens = export
        .map(|kind| {
            export_metadata(ExportMetadata {
                kind,
                is_network: true,
                group: group_path.as_ref(),
                fn_name: &fn_name,
                ctx_mut,
                params: &params,
                ret_inner: &ret_inner,
            })
        })
        .transpose()?
        .unwrap_or_else(TokenStream::new);

    Ok(quote::quote! {
        #(#attrs)*
        lyquid::__lyquid_categorize_methods!(
            { network(#group_tokens) export(#export_flag) fn #fn_name(#ctx_pattern #(, #params_ts)*) -> LyquidResult<#ret_inner> #body },
            {},
            {},
            {}
        );
        #export_tokens
    })
}

// Expands #[lyquid::method::instance], optionally handling upc(...) or oracle two-phase helpers.
fn expand_instance_function(attr: TokenStream, func: syn::ItemFn) -> syn::Result<TokenStream> {
    match parse_instance_attr(attr)? {
        InstanceAttr::Standard(MethodAttr {
            group: group_path,
            export,
        }) => {
            let parsed = parse_function_signature(func)?;
            let ctx_ident = parsed.ctx_ident;
            let ctx_mut = parsed.ctx_mut;
            let params = parsed.params;
            let ret_inner = parsed.ret_inner;
            let attrs = parsed.attrs;
            let fn_name = parsed.fn_name;
            let body = parsed.body;

            let group_tokens = match group_path.as_ref() {
                Some(path) => quote::quote!(#path),
                None => quote::quote!(main),
            };
            // Special-case oracle two-phase aggregate to a fixed ABI entrypoint.
            if let Some(path) = group_path.as_ref() &&
                let Some(oracle_name) = oracle_two_phase_name(path) &&
                fn_name == "aggregate"
            {
                if export.is_some() {
                    return Err(syn::Error::new_spanned(
                        fn_name,
                        "oracle two-phase aggregate does not support `export`",
                    ));
                }
                if ctx_mut {
                    return Err(syn::Error::new_spanned(
                        fn_name,
                        "oracle two-phase aggregate must take `ctx: &_`",
                    ));
                }
                if !params.is_empty() {
                    return Err(syn::Error::new_spanned(
                        fn_name,
                        "oracle two-phase aggregate must not take extra parameters",
                    ));
                }
                if !is_option_certified_call_params(&ret_inner) {
                    return Err(syn::Error::new_spanned(
                        ret_inner,
                        "oracle two-phase aggregate must return LyquidResult<Option<CertifiedCallParams>>",
                    ));
                }
                return Ok(quote::quote! {
                    #(#attrs)*
                    lyquid::__lyquid_categorize_methods!(
                        { instance(oracle::two_phase::#oracle_name) export(false) fn aggregate(&#ctx_ident) -> LyquidResult<Option<CertifiedCallParams>> #body },
                        {},
                        {},
                        {}
                    );
                });
            }
            let ctx_pattern = if ctx_mut {
                quote::quote! { &mut #ctx_ident }
            } else {
                quote::quote! { & #ctx_ident }
            };
            let params_ts = params.iter().map(|(ident, ty)| quote::quote! { #ident: #ty });
            let export_flag = if matches!(export.as_ref(), Some(ExportKind::Ethereum(_))) {
                quote::quote! { true }
            } else {
                quote::quote! { false }
            };

            let export_tokens = export
                .map(|kind| {
                    export_metadata(ExportMetadata {
                        kind,
                        is_network: false,
                        group: group_path.as_ref(),
                        fn_name: &fn_name,
                        ctx_mut,
                        params: &params,
                        ret_inner: &ret_inner,
                    })
                })
                .transpose()?
                .unwrap_or_else(TokenStream::new);

            Ok(quote::quote! {
                #(#attrs)*
                lyquid::__lyquid_categorize_methods!(
                    { instance(#group_tokens) export(#export_flag) fn #fn_name(#ctx_pattern #(, #params_ts)*) -> LyquidResult<#ret_inner> #body },
                    {},
                    {},
                    {}
                );
                #export_tokens
            })
        }
        InstanceAttr::Upc(upc_path) => expand_instance_upc_function(upc_path, func),
    }
}

// Lower constructor into the same wrapper shape used by generated network methods.
fn expand_constructor(parsed: ParsedConstructor, export: Option<ExportKind>) -> syn::Result<TokenStream> {
    let ParsedConstructor {
        ctx_ident,
        ctx_mut,
        params,
        attrs,
        fn_name: _,
        body,
    } = parsed;
    let ctor_name = quote::format_ident!("__lyquid_constructor");
    let ctx_init = if ctx_mut {
        quote::quote! { let mut #ctx_ident = __lyquid::NetworkContext::new(ctx)?; }
    } else {
        quote::quote! { let #ctx_ident = __lyquid::ImmutableNetworkContext::new(ctx)?; }
    };
    let mutable_flag = if ctx_mut {
        quote::quote! { true }
    } else {
        quote::quote! { false }
    };
    let export_flag = if export.is_some() {
        quote::quote! { true }
    } else {
        quote::quote! { false }
    };
    let params_ts = params.iter().map(|(ident, ty)| quote::quote! { #ident: #ty });
    let ctor_ret_inner = syn::parse_quote!(bool);

    let export_tokens = export
        .map(|kind| {
            export_metadata(ExportMetadata {
                kind,
                is_network: true,
                group: None,
                fn_name: &ctor_name,
                ctx_mut,
                params: &params,
                ret_inner: &ctor_ret_inner,
            })
        })
        .transpose()?
        .unwrap_or_else(TokenStream::new);

    Ok(quote::quote! {
        #(#attrs)*
        lyquid::__lyquid_wrap_methods!(
            "__lyquid_method_network",
            main (#mutable_flag, #export_flag) fn #ctor_name(#(#params_ts),*) -> LyquidResult<bool> {
                |ctx: lyquid::CallContext| -> LyquidResult<bool> {
                    use crate::__lyquid;
                    #ctx_init
                    let result: LyquidResult<bool> = (|| -> LyquidResult<bool> { #body; Ok(true) })();
                    drop(#ctx_ident);
                    result
                }
            }
        );
        #export_tokens
    })
}

enum InstanceAttr {
    Standard(MethodAttr),
    Upc(syn::Path),
}

// Lower upc(...) instance functions, rewriting signatures for response handlers.
fn expand_instance_upc_function(upc_path: syn::Path, func: syn::ItemFn) -> syn::Result<TokenStream> {
    let parsed = parse_function_signature(func)?;
    let ctx_ident = parsed.ctx_ident;
    let ctx_mut = parsed.ctx_mut;
    let params = parsed.params;
    let ret_inner = parsed.ret_inner;
    let attrs = parsed.attrs;
    let fn_name = parsed.fn_name;
    let body = parsed.body;

    let ctx_pattern = if ctx_mut {
        quote::quote! { &mut #ctx_ident }
    } else {
        quote::quote! { & #ctx_ident }
    };
    let is_response = upc_path.segments.first().is_some_and(|seg| seg.ident == "response");

    let (params_ts, ret_tokens): (Vec<TokenStream>, TokenStream) = if is_response {
        if ctx_mut {
            return Err(syn::Error::new_spanned(ctx_ident, "upc(response) must take `ctx: &_`"));
        }
        if params.len() != 1 {
            return Err(syn::Error::new_spanned(
                fn_name,
                "upc(response) must take exactly one parameter: `response: LyquidResult<T>`",
            ));
        }

        let Some(inner) = option_inner_type(&ret_inner) else {
            return Err(syn::Error::new_spanned(
                ret_inner,
                "upc(response) must return LyquidResult<Option<T>>",
            ));
        };

        let (returned_ident, _returned_ty) = &params[0];
        let params_ts = vec![quote::quote! { #returned_ident: LyquidResult<#inner> }];
        let ret_tokens = quote::quote! { LyquidResult<Option<#inner>> };
        (params_ts, ret_tokens)
    } else {
        let params_ts = params.iter().map(|(ident, ty)| quote::quote! { #ident: #ty }).collect();
        let ret_tokens = quote::quote! { LyquidResult<#ret_inner> };
        (params_ts, ret_tokens)
    };

    Ok(quote::quote! {
        #(#attrs)*
        lyquid::__lyquid_categorize_methods!(
            { instance(upc::#upc_path) fn #fn_name(#ctx_pattern #(, #params_ts)*) -> #ret_tokens #body },
            {},
            {},
            {}
        );
    })
}

fn option_inner_type(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    match &segment.arguments {
        syn::PathArguments::AngleBracketed(args) => {
            let mut iter = args.args.iter();
            match iter.next() {
                Some(syn::GenericArgument::Type(inner)) if iter.next().is_none() => Some(inner.clone()),
                _ => None,
            }
        }
        _ => None,
    }
}

// Parse #[lyquid::method::instance] arguments: group = foo::bar, or upc(...).
fn parse_instance_attr(attr: TokenStream) -> syn::Result<InstanceAttr> {
    if attr.is_empty() {
        return Ok(InstanceAttr::Standard(MethodAttr {
            group: None,
            export: None,
        }));
    }

    let mut iter = attr.clone().into_iter();
    let first = iter
        .next()
        .ok_or_else(|| syn::Error::new_spanned(&attr, "invalid attribute arguments"))?;

    match first {
        TokenTree::Ident(ident) if ident == "upc" => {
            let group = match iter.next() {
                Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis => group,
                Some(other) => {
                    return Err(syn::Error::new_spanned(
                        other,
                        "expected `upc(<role>)` for #[lyquid::method::instance]",
                    ));
                }
                None => {
                    return Err(syn::Error::new_spanned(
                        ident,
                        "expected `upc(<role>)` for #[lyquid::method::instance]",
                    ));
                }
            };
            if iter.next().is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "unexpected extra arguments for #[lyquid::method::instance]",
                ));
            }

            let upc_path: syn::Path = syn::parse2(group.stream())?;
            validate_group_path(&upc_path)?;
            Ok(InstanceAttr::Upc(upc_path))
        }
        _ => {
            let parsed = parse_method_attr(attr, "lyquid::method::instance")?;
            Ok(InstanceAttr::Standard(parsed))
        }
    }
}

fn parse_method_attr(attr: TokenStream, attr_name: &str) -> syn::Result<MethodAttr> {
    if attr.is_empty() {
        return Ok(MethodAttr {
            group: None,
            export: None,
        });
    }

    let parser = |input: syn::parse::ParseStream| -> syn::Result<MethodAttr> {
        let mut group = None;
        let mut export_kind = None::<String>;
        let mut http_method = None;
        let mut http_path_prefix = None;
        let mut eth_guard = None;

        while !input.is_empty() {
            let key: syn::Ident = input.parse()?;
            input.parse::<syn::Token![=]>()?;

            if key == "group" {
                let path: syn::Path = input.parse()?;
                validate_group_path(&path)?;
                if group.is_some() {
                    return Err(syn::Error::new_spanned(key, "duplicate `group` argument"));
                }
                group = Some(path);
            } else if key == "export" {
                let kind = if input.peek(syn::Ident) {
                    let ident: syn::Ident = input.parse()?;
                    ident.to_string()
                } else if input.peek(syn::LitStr) {
                    let lit: syn::LitStr = input.parse()?;
                    lit.value()
                } else {
                    return Err(syn::Error::new_spanned(
                        key,
                        "expected `export = eth` for #[lyquid::method::network/instance]",
                    ));
                };
                if export_kind.is_some() {
                    return Err(syn::Error::new_spanned(key, "duplicate `export` argument"));
                }
                match kind.as_str() {
                    "eth" | "http" => export_kind = Some(kind),
                    _ => {
                        return Err(syn::Error::new_spanned(
                            key,
                            "unsupported export kind; expected `eth` or `http`",
                        ))
                    }
                };
            } else if key == "method" {
                let lit: syn::LitStr = input.parse()?;
                if http_method.is_some() {
                    return Err(syn::Error::new_spanned(key, "duplicate `method` argument"));
                }
                http_method = Some(validate_http_export_method(lit)?);
            } else if key == "path_prefix" {
                let lit: syn::LitStr = input.parse()?;
                if http_path_prefix.is_some() {
                    return Err(syn::Error::new_spanned(key, "duplicate `path_prefix` argument"));
                }
                http_path_prefix = Some(canonical_http_path_prefix(lit)?);
            } else if key == "eth_guard" {
                let value: syn::Ident = input.parse()?;
                if eth_guard.is_some() {
                    return Err(syn::Error::new_spanned(key, "duplicate `eth_guard` argument"));
                }
                eth_guard = match value.to_string().as_str() {
                    "creator" => Some(EthExportGuard::Creator),
                    _ => {
                        return Err(syn::Error::new_spanned(
                            value,
                            "unsupported Ethereum export guard; expected `creator`",
                        ))
                    }
                };
            } else {
                return Err(syn::Error::new_spanned(
                    key,
                    format!(
                        "expected `group = foo::bar`, `export = eth`, `eth_guard = creator`, or `export = http, method = \"GET\", path_prefix = \"/api\"` for #[{attr_name}]"
                    ),
                ));
            }

            if input.peek(syn::Token![,]) {
                input.parse::<syn::Token![,]>()?;
            }
        }

        if !matches!(export_kind.as_deref(), Some("http")) && (http_method.is_some() || http_path_prefix.is_some()) {
            return Err(syn::Error::new(
                Span::call_site(),
                "`method` and `path_prefix` are only valid with `export = http`",
            ));
        }
        if !matches!(export_kind.as_deref(), Some("eth")) && eth_guard.is_some() {
            return Err(syn::Error::new(
                Span::call_site(),
                "`eth_guard` is only valid with `export = eth`",
            ));
        }

        let export = match export_kind.as_deref() {
            Some("http") => {
                let method = http_method
                    .ok_or_else(|| syn::Error::new(Span::call_site(), "`export = http` requires `method = \"...\"`"))?;
                let path_prefix = http_path_prefix.ok_or_else(|| {
                    syn::Error::new(Span::call_site(), "`export = http` requires `path_prefix = \"/...\"`")
                })?;
                Some(ExportKind::Http(HttpExportAttr { method, path_prefix }))
            }
            Some("eth") => Some(ExportKind::Ethereum(EthExportAttr {
                guard: eth_guard.unwrap_or(EthExportGuard::None),
            })),
            None => None,
            _ => unreachable!("unsupported export kind should be rejected while parsing"),
        };

        Ok(MethodAttr { group, export })
    };

    syn::parse::Parser::parse2(&parser, attr)
}

fn validate_http_export_method(lit: syn::LitStr) -> syn::Result<String> {
    let method = lit.value();
    match method.as_str() {
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "*" => Ok(method),
        _ => Err(syn::Error::new_spanned(
            lit,
            "unsupported HTTP export method; expected GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, or *",
        )),
    }
}

fn canonical_http_path_prefix(lit: syn::LitStr) -> syn::Result<String> {
    let prefix = lit.value();
    if !prefix.starts_with('/') {
        return Err(syn::Error::new_spanned(
            lit,
            "`path_prefix` must be an absolute path starting with `/`",
        ));
    }
    if prefix.contains('?') || prefix.contains('#') {
        return Err(syn::Error::new_spanned(
            lit,
            "`path_prefix` must not include a query string or fragment",
        ));
    }
    if prefix
        .chars()
        .any(|ch| matches!(ch, '{' | '}' | '*' | '[' | ']' | '(' | ')' | ':'))
    {
        return Err(syn::Error::new_spanned(
            lit,
            "`path_prefix` is prefix-only and must not contain path parameters, wildcards, or regex syntax",
        ));
    }

    let canonical = if prefix == "/" {
        prefix
    } else {
        prefix.trim_end_matches('/').to_owned()
    };
    if canonical.is_empty() {
        Ok("/".to_owned())
    } else if canonical != "/" && canonical.split('/').skip(1).any(str::is_empty) {
        Err(syn::Error::new_spanned(
            lit,
            "`path_prefix` must not contain empty path segments",
        ))
    } else {
        Ok(canonical)
    }
}

fn group_path_string(group: Option<&syn::Path>) -> String {
    match group {
        None => "main".to_string(),
        Some(path) => path
            .segments
            .iter()
            .map(|seg| seg.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
    }
}

struct ExportMetadata<'a> {
    kind: ExportKind,
    is_network: bool,
    group: Option<&'a syn::Path>,
    fn_name: &'a syn::Ident,
    ctx_mut: bool,
    params: &'a [(syn::Ident, syn::Type)],
    ret_inner: &'a syn::Type,
}

fn export_metadata(input: ExportMetadata<'_>) -> syn::Result<TokenStream> {
    let ExportMetadata {
        kind,
        is_network,
        group,
        fn_name,
        ctx_mut,
        params,
        ret_inner,
    } = input;
    match kind {
        ExportKind::Ethereum(eth) => export_metadata_eth(is_network, group, fn_name, ctx_mut, params, ret_inner, &eth),
        ExportKind::Http(http) => export_metadata_http(is_network, group, fn_name, params, ret_inner, &http),
    }
}

fn export_metadata_eth(
    is_network: bool, group: Option<&syn::Path>, fn_name: &syn::Ident, ctx_mut: bool,
    params: &[(syn::Ident, syn::Type)], ret_inner: &syn::Type, eth: &EthExportAttr,
) -> syn::Result<TokenStream> {
    let group_string = group_path_string(group);
    let method_string = fn_name.to_string();
    if matches!(eth.guard, EthExportGuard::Creator) {
        if method_string == "__lyquid_constructor" {
            return Err(syn::Error::new_spanned(
                fn_name,
                "`eth_guard = creator` is not supported on constructors",
            ));
        }
        if !is_network || !ctx_mut || !matches!(group_string.as_str(), "main" | "node") {
            return Err(syn::Error::new_spanned(
                fn_name,
                "`eth_guard = creator` is only supported on mutable network Ethereum exports in the `main` or `node` group",
            ));
        }
    }
    let param_types = params
        .iter()
        .map(|(_, ty)| quote::quote! { <#ty as lyquid::runtime::ethabi::EthAbiType>::DESC })
        .collect::<Vec<_>>();
    let param_count = param_types.len();
    let section_name = syn::LitStr::new("lyquor.method.export.eth", Span::call_site());
    let category = if is_network {
        quote::quote! { lyquid::consts::CATEGORY_NETWORK }
    } else {
        quote::quote! { lyquid::consts::CATEGORY_INSTANCE }
    };
    let mutable = if ctx_mut {
        quote::quote! { true }
    } else {
        quote::quote! { false }
    };
    let eth_guard = match eth.guard {
        EthExportGuard::None => quote::quote! { lyquid::consts::ETH_GUARD_NONE },
        EthExportGuard::Creator => quote::quote! { lyquid::consts::ETH_GUARD_CREATOR },
    };

    Ok(quote::quote! {
        #[doc(hidden)]
        const _: () = {
            const GROUP: &str = #group_string;
            const METHOD: &str = #method_string;
            const PARAM_COUNT: usize = #param_count;
            const PARAM_TYPES: [lyquid::runtime::ethabi::EthAbiTypeDesc; PARAM_COUNT] = [#(#param_types,)*];
            const RETURN_TYPES: &'static [lyquid::runtime::ethabi::EthAbiTypeDesc] =
                <#ret_inner as lyquid::runtime::ethabi::EthAbiReturn>::TYPES;

            const LEN: usize = lyquid::consts::export_len(
                GROUP,
                METHOD,
                &PARAM_TYPES,
                RETURN_TYPES,
            );

            #[unsafe(link_section = #section_name)]
            #[used]
            static EXPORT: [u8; LEN] = lyquid::consts::export_encode_with_guard::<LEN>(
                #category,
                #mutable,
                #eth_guard,
                GROUP,
                METHOD,
                &PARAM_TYPES,
                RETURN_TYPES,
            );
        };
    })
}

fn export_metadata_http(
    is_network: bool, group: Option<&syn::Path>, fn_name: &syn::Ident, params: &[(syn::Ident, syn::Type)],
    ret_inner: &syn::Type, http: &HttpExportAttr,
) -> syn::Result<TokenStream> {
    if is_network {
        return Err(syn::Error::new_spanned(
            fn_name,
            "`export = http` is only supported on #[lyquid::method::instance]",
        ));
    }
    if params.len() != 1 {
        return Err(syn::Error::new_spanned(
            fn_name,
            "HTTP exports must take exactly one request parameter: `req: http::Request`",
        ));
    }
    let (_, param_ty) = &params[0];
    if !is_http_type(param_ty, "Request") {
        return Err(syn::Error::new_spanned(
            param_ty,
            "HTTP export request parameter must be `http::Request`",
        ));
    }
    if !is_http_type(ret_inner, "Response") {
        return Err(syn::Error::new_spanned(
            ret_inner,
            "HTTP export return type must be `LyquidResult<http::Response>`",
        ));
    }
    let group_string = group_path_string(group);
    let method_string = fn_name.to_string();
    let http_method = &http.method;
    let path_prefix = &http.path_prefix;
    validate_http_export_component_len("group", &group_string, fn_name)?;
    validate_http_export_component_len("method", &method_string, fn_name)?;
    validate_http_export_component_len("HTTP method", http_method, fn_name)?;
    validate_http_export_component_len("path_prefix", path_prefix, fn_name)?;
    let section_name = syn::LitStr::new("lyquor.method.export.http", Span::call_site());

    Ok(quote::quote! {
        #[doc(hidden)]
        const _: () = {
            const GROUP: &str = #group_string;
            const METHOD: &str = #method_string;
            const HTTP_METHOD: &str = #http_method;
            const PATH_PREFIX: &str = #path_prefix;
            const LEN: usize = lyquid::consts::http_export_len(
                GROUP,
                METHOD,
                HTTP_METHOD,
                PATH_PREFIX,
            );

            #[unsafe(link_section = #section_name)]
            #[used]
            static EXPORT: [u8; LEN] = lyquid::consts::http_export_encode::<LEN>(
                lyquid::consts::CATEGORY_INSTANCE,
                GROUP,
                METHOD,
                HTTP_METHOD,
                PATH_PREFIX,
            );
        };
    })
}

fn validate_http_export_component_len<T: quote::ToTokens>(label: &str, value: &str, span: T) -> syn::Result<()> {
    if value.len() <= u16::MAX as usize {
        return Ok(());
    }
    Err(syn::Error::new_spanned(
        span,
        format!(
            "HTTP export {label} is too long to encode; maximum length is {} bytes",
            u16::MAX
        ),
    ))
}

fn is_http_type(ty: &syn::Type, expected: &str) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    if path.qself.is_some() || path.path.segments.len() < 2 {
        return false;
    }
    let mut segments = path.path.segments.iter().rev();
    let Some(last) = segments.next() else {
        return false;
    };
    let Some(prev) = segments.next() else {
        return false;
    };
    last.ident == expected && prev.ident == "http" && matches!(&last.arguments, syn::PathArguments::None)
}

// Parses group metadata and validates it as a relative path (foo::bar).
fn parse_method_group(attr: TokenStream, attr_name: &str) -> syn::Result<Option<syn::Path>> {
    if attr.is_empty() {
        return Ok(None);
    }

    let parser = |input: syn::parse::ParseStream| -> syn::Result<syn::Path> {
        let key: syn::Ident = input.parse()?;
        if key != "group" {
            return Err(syn::Error::new_spanned(
                key,
                format!("expected `group = foo::bar` for #[{attr_name}]"),
            ));
        }
        input.parse::<syn::Token![=]>()?;
        let path: syn::Path = input.parse()?;

        if input.peek(syn::Token![,]) {
            input.parse::<syn::Token![,]>()?;
            if !input.is_empty() {
                return Err(input.error("unexpected extra arguments"));
            }
        } else if !input.is_empty() {
            return Err(input.error("unexpected extra arguments"));
        }

        Ok(path)
    };

    let parsed = syn::parse::Parser::parse2(&parser, attr)?;
    validate_group_path(&parsed)?;
    Ok(Some(parsed))
}

fn validate_group_path(path: &syn::Path) -> syn::Result<()> {
    if path.leading_colon.is_some() {
        return Err(syn::Error::new_spanned(
            path,
            "group must be a relative path like `foo::bar`",
        ));
    }
    if path.segments.iter().any(|seg| !seg.arguments.is_empty()) {
        return Err(syn::Error::new_spanned(
            path,
            "group path must not contain generic arguments",
        ));
    }
    Ok(())
}

fn oracle_two_phase_name(path: &syn::Path) -> Option<syn::Ident> {
    let mut iter = path.segments.iter();
    let oracle = iter.next()?;
    let two_phase = iter.next()?;
    let name = iter.next()?;
    if oracle.ident != "oracle" || two_phase.ident != "two_phase" {
        return None;
    }
    if iter.next().is_some() {
        return None;
    }
    Some(name.ident.clone())
}

fn is_option_certified_call_params(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    let option_seg = match path.path.segments.last() {
        Some(seg) if seg.ident == "Option" => seg,
        _ => return false,
    };
    let syn::PathArguments::AngleBracketed(args) = &option_seg.arguments else {
        return false;
    };
    let mut iter = args.args.iter();
    let Some(syn::GenericArgument::Type(inner)) = iter.next() else {
        return false;
    };
    if iter.next().is_some() {
        return false;
    }
    let syn::Type::Path(inner_path) = inner else {
        return false;
    };
    inner_path
        .path
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "CertifiedCallParams")
}

// Internal helper: prefixes a function or module name.
/// Rewrites an item with a generated export prefix for Lyquid runtime entry points.
#[proc_macro_attribute]
pub fn prefix_item(attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    use quote::ToTokens;
    match syn::parse_macro_input!(item as syn::Item) {
        syn::Item::Fn(mut func) => {
            func.sig.ident = add_prefix(attr.into(), func.sig.ident);
            func.to_token_stream()
        }
        syn::Item::Mod(mut mo) => {
            mo.ident = add_prefix(attr.into(), mo.ident);
            mo.to_token_stream()
        }
        _ => panic!("unsupported item"),
    }
    .into()
}

// #[lyquid::method::network]
/// Marks a function as a network Lyquid method and emits the runtime entry point metadata.
#[proc_macro_attribute]
pub fn network_function(attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let func = syn::parse_macro_input!(item as syn::ItemFn);
    match expand_network_function(attr.into(), func) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

// #[lyquid::method::instance]
/// Marks a function as an instance Lyquid method and emits the runtime entry point metadata.
#[proc_macro_attribute]
pub fn instance_function(attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let func = syn::parse_macro_input!(item as syn::ItemFn);
    match expand_instance_function(attr.into(), func) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

// Internal helper: prefix a call site to match prefixed items.
/// Expands a prefixed runtime call expression used by generated Lyquid wrappers.
#[proc_macro]
pub fn prefix_call(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    struct Input {
        attr: TokenStream,
        _comma: syn::Token![,],
        expr: syn::Expr,
    }

    impl syn::parse::Parse for Input {
        fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
            let content;
            syn::parenthesized!(content in input);
            Ok(Self {
                attr: content.parse()?,
                _comma: input.parse()?,
                expr: input.parse()?,
            })
        }
    }

    let Input { attr, expr, .. } = syn::parse_macro_input!(input as Input);

    match expr {
        syn::Expr::Call(mut call) => {
            if let syn::Expr::Path(ref mut func_path) = *call.func {
                if let Some(ident) = func_path.path.get_ident() {
                    func_path.path.segments[0].ident = add_prefix(attr, ident.clone());
                }
                quote::quote!(#call).into()
            } else {
                panic!("expected a simple function call");
            }
        }
        syn::Expr::Path(path_expr) => {
            if let Some(ident) = path_expr.path.get_ident() {
                let new_ident = add_prefix(attr, ident.clone());
                quote::quote!(#new_ident).into()
            } else {
                quote::quote!(#path_expr).into()
            }
        }
        _ => panic!("expected a function call or an identifier"),
    }
}

/// Generates Lyquid state accessors and the initialization entry point for state variables.
#[proc_macro]
pub fn setup_lyquid_state_variables(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let mut toplevel_tokens = TokenStream::from(item).into_iter(); // use proc_macro2 instead of proc_macro as it is more convenient
    let struct_suffix = next_token_is_ident(&mut toplevel_tokens).expect("expect struct suffix name");
    let init_func = next_token_is_ident(&mut toplevel_tokens).expect("expect init func name");
    let categories = next_token_is_group(&mut toplevel_tokens).expect("expect a list of categories");
    let mut cats = HashMap::new();
    for token in categories.stream() {
        let grp = token_is_group(token).expect("expect category info");
        let mut iter = grp.stream().into_iter();
        let cat_id = next_token_is_ident(&mut iter).expect("expect category identifer");
        let cat_prefix = next_token_is_ident(&mut iter).expect("expect category prefix");
        cats.insert(cat_id.to_string(), (iter.collect::<TokenStream>(), cat_prefix));
    }
    let mut struct_fields = HashMap::new(); // maps from categories to a token stream of struct fields
    let mut struct_inits = HashMap::new(); // maps from categories to a token stream of field initializers
    let mut var_setup = TokenStream::new();

    //let mut extra = TokenStream::new();
    for def in toplevel_tokens {
        let mut def_iter = token_is_group(def)
            .expect("expect state variable definition")
            .stream()
            .into_iter();
        let cat = next_token_is_ident(&mut def_iter).expect("expect storage category");
        let mut cat_str = cat.to_string();
        let name = next_token_is_ident(&mut def_iter).expect("expect variable identifer");
        let name_str = name.to_string();
        let type_;
        let init;

        match cat_str.as_str() {
            "oracle" => {
                cat_str = "network".to_string();
                type_ = quote::quote! { runtime::oracle::StateVar<'static> };
                init = quote::quote! { runtime::oracle::StateVar::new(stringify!(#name)) };
            }
            _ => {
                type_ = def_iter.next().expect("expect variable type").into();
                init = next_token_is_group(&mut def_iter)
                    .expect("expect an initializer")
                    .stream();
            }
        }

        let mut type_ = type_;
        let mut init = init;

        let Some((cat_value, _)) = cats.get(&cat_str) else {
            panic!("invalid category {cat}")
        };

        let field_ts = struct_fields.entry(cat_str.clone()).or_insert_with(TokenStream::new);
        let init_ts = struct_inits.entry(cat_str.clone()).or_insert_with(TokenStream::new);

        // Switch to the correct allocator.
        let cat_num: u8 = match cat_str.as_str() {
            "instance" => 0x1,
            "network" => 0x2,
            _ => panic!("Unknown category for the allocator."),
        };
        init = quote::quote! {{
            runtime::set_allocator_category(#cat_num);
            #init
        }};

        if cat_str == "instance" {
            init = quote::quote! {runtime::sync::RwLock::new(#init)};
            type_ = quote::quote! {runtime::sync::RwLock<#type_>};
        }

        var_setup.extend([quote::quote! {
            // the pointer (only need to do it once, upon initialization of the instance's
            // LiteMemory)
            let ptr: *mut (#type_) = Box::leak(Box::new(#init));
            let bytes = (ptr as u64).to_be_bytes();
            pa.set(#cat_value, #name_str.as_bytes(), &bytes).expect(FAIL_WRITE_STATE);
        }]);

        field_ts.extend([quote::quote! {
            pub #name: &'static mut (#type_),
        }]);

        init_ts.extend([quote::quote! {
            #name: {
                // retrieve the pointer for Box<T>
                let bytes = pa.get(#cat_value, &#name_str.as_bytes())?.ok_or(LyquidError::Init)?;
                let addr = u64::from_be_bytes(bytes.try_into().map_err(|_| LyquidError::Init)?);
                unsafe { &mut *(addr as *mut (#type_)) }
            },
        }]);
    }

    var_setup.extend(
        [quote::quote! {
            // the pointer (only need to do it once, upon initialization of the instance's
            // LiteMemory)
            runtime::set_allocator_category(0x2);
            let ptr: *mut runtime::internal::BuiltinNetworkState = Box::leak(Box::new(runtime::internal::BuiltinNetworkState::new()));
            let bytes = (ptr as u64).to_be_bytes();
            internal_pa.set(StateCategory::Network, "network".as_bytes(), &bytes).expect(FAIL_WRITE_STATE);
        }]
    );
    var_setup.extend(
        [quote::quote! {
            // the pointer (only need to do it once, upon initialization of the instance's
            // LiteMemory)
            runtime::set_allocator_category(0x1);
            let ptr: *mut runtime::internal::BuiltinInstanceState = Box::leak(Box::new(runtime::internal::BuiltinInstanceState::new()));
            let bytes = (ptr as u64).to_be_bytes();
            internal_pa.set(StateCategory::Instance, "instance".as_bytes(), &bytes).expect(FAIL_WRITE_STATE);
        }]
    );

    struct_fields
        .entry("network".to_string())
        .or_insert_with(TokenStream::new)
        .extend([quote::quote! {
            #[allow(dead_code)]
            __internal: &'static mut runtime::internal::BuiltinNetworkState,
        }]);
    struct_inits
        .entry("network".to_string())
        .or_insert_with(TokenStream::new)
        .extend([quote::quote! {
            __internal: {
                // retrieve the pointer for Box<T>
                let bytes = internal_pa.get(StateCategory::Network, "network".as_bytes())?.ok_or(LyquidError::Init)?;
                let addr = u64::from_be_bytes(bytes.try_into().map_err(|_| LyquidError::Init)?);
                unsafe { &mut *(addr as *mut runtime::internal::BuiltinNetworkState) }
            },
        }]);

    struct_fields
        .entry("instance".to_string())
        .or_insert_with(TokenStream::new)
        .extend([quote::quote! {
            #[allow(dead_code)]
            __internal: &'static mut runtime::internal::BuiltinInstanceState,
        }]);
    struct_inits
        .entry("instance".to_string())
        .or_insert_with(TokenStream::new)
        .extend([quote::quote! {
            __internal: {
                // retrieve the pointer for Box<T>
                let bytes = internal_pa.get(StateCategory::Instance, "instance".as_bytes())?.ok_or(LyquidError::Init)?;
                let addr = u64::from_be_bytes(bytes.try_into().map_err(|_| LyquidError::Init)?);
                unsafe { &mut *(addr as *mut runtime::internal::BuiltinInstanceState) }
            },
        }]);

    // now we summary up each category and generate output
    let mut structs = TokenStream::new();
    for (cat, (_, cat_prefix)) in &cats {
        let field_ts = struct_fields.entry(cat.clone()).or_insert_with(TokenStream::new);
        let init_ts = struct_inits.entry(cat.clone()).or_insert_with(TokenStream::new);
        let sname = quote::format_ident!("{}{}", cat_prefix, struct_suffix);
        structs.extend([quote::quote! {
        /// Macro-generated Lyquid state accessor for one state category.
        pub struct #sname {
                #field_ts
            }

            impl runtime::internal::StateAccessor for #sname {
                fn new() -> Result<Self, LyquidError> {
                    let internal_pa = runtime::internal::PrefixedAccess::new(Vec::from(lyquid::INTERNAL_STATE_PREFIX));
                    let pa = runtime::internal::PrefixedAccess::new(Vec::from(lyquid::VAR_CATALOG_PREFIX));
                    Ok(Self {
                        #init_ts
                    })
                }
            }
        }]);
    }
    quote::quote! {
        #structs

        //#extra

        #[unsafe(no_mangle)]
        unsafe fn #init_func(category: u32) {
            const FAIL_WRITE_STATE: &str = "cannot write to low-level state store during LiteMemory initialization";
            let internal_pa = runtime::internal::PrefixedAccess::new(Vec::from(lyquid::INTERNAL_STATE_PREFIX));
            let pa = runtime::internal::PrefixedAccess::new(Vec::from(lyquid::VAR_CATALOG_PREFIX));
            #var_setup
            runtime::set_allocator_category(category as u8);
        }
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_export_attr_accepts_supported_method_and_canonical_prefix() {
        let attr = parse_method_attr(
            quote::quote!(export = http, method = "POST", path_prefix = "/api/"),
            "lyquid::method::instance",
        )
        .expect("HTTP export attribute should parse");

        let Some(ExportKind::Http(http)) = attr.export else {
            panic!("HTTP metadata should be present");
        };
        assert_eq!(http.method, "POST");
        assert_eq!(http.path_prefix, "/api");
    }

    #[test]
    fn eth_export_attr_accepts_creator_guard() {
        let attr = parse_method_attr(
            quote::quote!(eth_guard = creator, export = eth),
            "lyquid::method::network",
        )
        .expect("Ethereum export guard should parse");

        let Some(ExportKind::Ethereum(eth)) = attr.export else {
            panic!("Ethereum metadata should be present");
        };
        assert!(matches!(eth.guard, EthExportGuard::Creator));
    }

    #[test]
    fn eth_export_attr_rejects_guard_without_eth_export() {
        let Err(err) = parse_method_attr(quote::quote!(eth_guard = creator), "lyquid::method::network") else {
            panic!("guard without an Ethereum export should fail")
        };
        assert!(err.to_string().contains("only valid with `export = eth`"));
    }

    #[test]
    fn http_export_attr_rejects_unsupported_method() {
        let Err(err) = parse_method_attr(
            quote::quote!(export = http, method = "CONNECT", path_prefix = "/api"),
            "lyquid::method::instance",
        ) else {
            panic!("unsupported HTTP method should fail")
        };
        assert!(err.to_string().contains("unsupported HTTP export method"));
    }

    #[test]
    fn http_export_attr_rejects_non_absolute_prefix() {
        let Err(err) = parse_method_attr(
            quote::quote!(export = http, method = "GET", path_prefix = "api"),
            "lyquid::method::instance",
        ) else {
            panic!("non-absolute path prefix should fail")
        };
        assert!(err.to_string().contains("absolute path"));
    }

    #[test]
    fn http_export_signature_validation_accepts_request_response_pair() {
        export_metadata_http(
            false,
            None,
            &quote::format_ident!("api"),
            &[(quote::format_ident!("req"), syn::parse_quote!(http::Request))],
            &syn::parse_quote!(http::Response),
            &HttpExportAttr {
                method: "GET".to_owned(),
                path_prefix: "/api".to_owned(),
            },
        )
        .expect("valid HTTP export signature should emit metadata");
    }

    #[test]
    fn eth_export_signature_validation_rejects_creator_guard_without_public_wrapper() {
        let Err(err) = export_metadata_eth(
            true,
            Some(&syn::parse_quote!(aux)),
            &quote::format_ident!("setup"),
            true,
            &[],
            &syn::parse_quote!(()),
            &EthExportAttr {
                guard: EthExportGuard::Creator,
            },
        ) else {
            panic!("creator guard on an unwrapped group should fail")
        };
        assert!(err.to_string().contains("mutable network Ethereum exports"));
    }

    #[test]
    fn http_export_signature_validation_rejects_network_methods() {
        let Err(err) = export_metadata_http(
            true,
            None,
            &quote::format_ident!("api"),
            &[(quote::format_ident!("req"), syn::parse_quote!(http::Request))],
            &syn::parse_quote!(http::Response),
            &HttpExportAttr {
                method: "GET".to_owned(),
                path_prefix: "/api".to_owned(),
            },
        ) else {
            panic!("network HTTP export should fail")
        };
        assert!(err.to_string().contains("only supported on"));
    }

    #[test]
    fn http_export_signature_validation_rejects_oversized_metadata() {
        let path_prefix = format!("/{}", "a".repeat(u16::MAX as usize));
        let Err(err) = export_metadata_http(
            false,
            None,
            &quote::format_ident!("api"),
            &[(quote::format_ident!("req"), syn::parse_quote!(http::Request))],
            &syn::parse_quote!(http::Response),
            &HttpExportAttr {
                method: "GET".to_owned(),
                path_prefix,
            },
        ) else {
            panic!("oversized HTTP metadata should fail")
        };
        assert!(err.to_string().contains("path_prefix"));
    }
}
