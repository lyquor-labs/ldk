#![allow(dead_code)]

use proc_macro;
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
    for t in TokenStream::from(attr).into_iter() {
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
                for token in g.stream().into_iter() {
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

#[derive(Clone, Copy)]
enum ExportKind {
    Ethereum,
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
            let ctx_ref = match &*pat_type.ty {
                syn::Type::Reference(reference) => reference,
                _ => {
                    return Err(syn::Error::new_spanned(
                        &pat_type.ty,
                        "context parameter must be a reference: `ctx: &mut _` or `ctx: &_`",
                    ));
                }
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
            let ty_path = match &**ty {
                syn::Type::Path(path) => path,
                _ => {
                    return Err(syn::Error::new_spanned(&output, "return type must be LyquidResult<T>"));
                }
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
        let parsed = parse_constructor_signature(func)?;
        return expand_constructor(parsed, parsed_attr.export);
    }

    // Parse optional group metadata and lower to __lyquid_categorize_methods.
    let MethodAttr {
        group: group_path,
        export,
    } = parse_method_attr(attr, "lyquid::method::network")?;
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
    let export_flag = if export.is_some() {
        quote::quote! { true }
    } else {
        quote::quote! { false }
    };

    let export_tokens = export
        .map(|kind| export_metadata(kind, true, group_path.as_ref(), &fn_name, ctx_mut, &params, &ret_inner))
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
            if let Some(path) = group_path.as_ref() {
                if let Some(oracle_name) = oracle_two_phase_name(&path) {
                    if fn_name == "aggregate" {
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
                }
            }
            let ctx_pattern = if ctx_mut {
                quote::quote! { &mut #ctx_ident }
            } else {
                quote::quote! { & #ctx_ident }
            };
            let params_ts = params.iter().map(|(ident, ty)| quote::quote! { #ident: #ty });
            let export_flag = if export.is_some() {
                quote::quote! { true }
            } else {
                quote::quote! { false }
            };

            let export_tokens = export
                .map(|kind| export_metadata(kind, false, group_path.as_ref(), &fn_name, ctx_mut, &params, &ret_inner))
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

// Lower constructor into the same wrapper shape used by legacy lyquid::method!.
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

    let export_tokens = export
        .map(|kind| export_metadata(kind, true, None, &ctor_name, ctx_mut, &params, &syn::parse_quote!(bool)))
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
    let is_response = upc_path
        .segments
        .first()
        .map(|seg| seg.ident == "response")
        .unwrap_or(false);

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

        let inner = match option_inner_type(&ret_inner) {
            Some(inner) => inner,
            None => {
                return Err(syn::Error::new_spanned(
                    ret_inner,
                    "upc(response) must return LyquidResult<Option<T>>",
                ));
            }
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
    let path = match ty {
        syn::Type::Path(path) => path,
        _ => return None,
    };
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
        let mut export = None;

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
                if export.is_some() {
                    return Err(syn::Error::new_spanned(key, "duplicate `export` argument"));
                }
                export = match kind.as_str() {
                    "eth" => Some(ExportKind::Ethereum),
                    _ => return Err(syn::Error::new_spanned(key, "unsupported export kind; expected `eth`")),
                };
            } else {
                return Err(syn::Error::new_spanned(
                    key,
                    format!("expected `group = foo::bar` or `export = eth` for #[{attr_name}]"),
                ));
            }

            if input.peek(syn::Token![,]) {
                input.parse::<syn::Token![,]>()?;
            }
        }

        Ok(MethodAttr { group, export })
    };

    syn::parse::Parser::parse2(&parser, attr)
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

fn export_metadata(
    kind: ExportKind, is_network: bool, group: Option<&syn::Path>, fn_name: &syn::Ident, ctx_mut: bool,
    params: &[(syn::Ident, syn::Type)], ret_inner: &syn::Type,
) -> syn::Result<TokenStream> {
    match kind {
        ExportKind::Ethereum => export_metadata_eth(is_network, group, fn_name, ctx_mut, params, ret_inner),
    }
}

fn export_metadata_eth(
    is_network: bool, group: Option<&syn::Path>, fn_name: &syn::Ident, ctx_mut: bool,
    params: &[(syn::Ident, syn::Type)], ret_inner: &syn::Type,
) -> syn::Result<TokenStream> {
    let group_string = group_path_string(group);
    let method_string = fn_name.to_string();
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
            static EXPORT: [u8; LEN] = lyquid::consts::export_encode::<LEN>(
                #category,
                #mutable,
                GROUP,
                METHOD,
                &PARAM_TYPES,
                RETURN_TYPES,
            );
        };
    })
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
    let inner = match iter.next() {
        Some(syn::GenericArgument::Type(inner)) => inner,
        _ => return false,
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
        .map(|seg| seg.ident == "CertifiedCallParams")
        .unwrap_or(false)
}

// Internal helper: prefixes a function or module name.
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
#[proc_macro_attribute]
pub fn network_function(attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let func = syn::parse_macro_input!(item as syn::ItemFn);
    match expand_network_function(attr.into(), func) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

// #[lyquid::method::instance]
#[proc_macro_attribute]
pub fn instance_function(attr: proc_macro::TokenStream, item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let func = syn::parse_macro_input!(item as syn::ItemFn);
    match expand_instance_function(attr.into(), func) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

// Internal helper: prefix a call site to match prefixed items.
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

#[proc_macro]
pub fn setup_lyquid_state_variables(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let mut toplevel_tokens = TokenStream::from(item).into_iter(); // use proc_macro2 instead of proc_macro as it is more convenient
    let struct_suffix = next_token_is_ident(&mut toplevel_tokens).expect("expect struct suffix name");
    let init_func = next_token_is_ident(&mut toplevel_tokens).expect("expect init func name");
    let categories = next_token_is_group(&mut toplevel_tokens).expect("expect a list of categories");
    let mut cats = HashMap::new();
    for token in categories.stream().into_iter() {
        let grp = token_is_group(token).expect("expect category info");
        let mut iter = grp.stream().into_iter();
        let cat_id = next_token_is_ident(&mut iter).expect("expect category identifer");
        let cat_prefix = next_token_is_ident(&mut iter).expect("expect category prefix");
        cats.insert(cat_id.to_string(), (TokenStream::from_iter(iter), cat_prefix));
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
                type_ = quote::quote! { runtime::oracle::OracleSrc };
                init = quote::quote! { runtime::oracle::OracleSrc::new(#name_str) };
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

        let (cat_value, _) = match cats.get(&cat_str) {
            Some(v) => v,
            None => panic!("invalid category {}", cat.to_string()),
        };

        let field_ts = struct_fields
            .entry(cat_str.clone())
            .or_insert_with(|| TokenStream::new());
        let init_ts = struct_inits
            .entry(cat_str.clone())
            .or_insert_with(|| TokenStream::new());

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

        if cat == "instance" {
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
            let ptr: *mut runtime::internal::BuiltinNetworkState = Box::leak(Box::new(runtime::internal::BuiltinNetworkState::new()));
            let bytes = (ptr as u64).to_be_bytes();
            internal_pa.set(StateCategory::Network, "network".as_bytes(), &bytes).expect(FAIL_WRITE_STATE);
        }]
    );

    struct_fields
        .entry("network".to_string())
        .or_insert_with(|| TokenStream::new())
        .extend([quote::quote! {
            pub __internal: &'static mut runtime::internal::BuiltinNetworkState,
        }]);
    struct_inits
        .entry("network".to_string())
        .or_insert_with(|| TokenStream::new())
        .extend([quote::quote! {
            __internal: {
                // retrieve the pointer for Box<T>
                let bytes = internal_pa.get(StateCategory::Network, "network".as_bytes())?.ok_or(LyquidError::Init)?;
                let addr = u64::from_be_bytes(bytes.try_into().map_err(|_| LyquidError::Init)?);
                unsafe { &mut *(addr as *mut runtime::internal::BuiltinNetworkState) }
            },
        }]);

    // now we summary up each category and generate output
    let mut structs = TokenStream::new();
    for (cat, (_, cat_prefix)) in cats.iter() {
        let field_ts = struct_fields.entry(cat.clone()).or_insert_with(|| TokenStream::new());
        let init_ts = struct_inits.entry(cat.clone()).or_insert_with(|| TokenStream::new());
        let sname = quote::format_ident!("{}{}", cat_prefix, struct_suffix);
        structs.extend([quote::quote! {
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
