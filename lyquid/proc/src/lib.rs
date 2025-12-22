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

#[proc_macro]
pub fn prefix_call(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    struct Input {
        attr: TokenStream,
        _comma: syn::Token![,],
        call: syn::Expr,
    }

    impl syn::parse::Parse for Input {
        fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
            let content;
            syn::parenthesized!(content in input);
            Ok(Self {
                attr: content.parse()?,
                _comma: input.parse()?,
                call: input.parse()?,
            })
        }
    }

    let Input { attr, call, .. } = syn::parse_macro_input!(input as Input);

    if let syn::Expr::Call(mut call) = call {
        if let syn::Expr::Path(ref mut func_path) = *call.func {
            if let Some(ident) = func_path.path.get_ident() {
                func_path.path.segments[0].ident = add_prefix(attr, ident.clone());
            }
            return quote::quote!(#call).into();
        }
    }
    panic!("expected a function call");
}

fn oracle_codegen(name: &Ident, output: &mut TokenStream) {
    output.extend(quote::quote! {
        lyquid::method! {
            upc(response::oracle::committee::#name) fn validate(&ctx, resp: LyquidResult<oracle::OracleResponse>) -> LyquidResult<Option< Option<oracle::OracleCert> >> {
                let cache = ctx.cache.get_or_init(|| {
                    let msg = lyquor_primitives::decode_by_fields!(&ctx.input, msg: oracle::OracleMessage)
                        .expect("invalid oracle message in UPC input")
                        .msg;
                    let msg_hash: Hash = lyquor_primitives::blake3::hash(&lyquor_primitives::encode_object(&msg));
                    oracle::Aggregation::new(msg.header, msg_hash)
                });
                if let Ok(resp) = resp {
                    return Ok(cache.add_response(ctx.from, resp, &ctx.network.#name))
                }
                Ok(None)
            }
        }
    });
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
        let cat_alloc = next_token_is_ident(&mut iter).expect("expect category allocator");
        let cat_prefix = next_token_is_ident(&mut iter).expect("expect category prefix");
        cats.insert(
            cat_id.to_string(),
            (cat_alloc, TokenStream::from_iter(iter), cat_prefix),
        );
    }
    let mut struct_fields = HashMap::new(); // maps from categories to a token stream of struct fields
    let mut struct_inits = HashMap::new(); // maps from categories to a token stream of field initializers
    let mut var_setup = TokenStream::new();

    let mut extra = TokenStream::new();
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
                type_ = quote::quote! { lyquid::runtime::network::Oracle };
                init = quote::quote! { lyquid::runtime::network::Oracle::new(#name_str) };
                oracle_codegen(&name, &mut extra);
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

        let (cat_alloc, cat_value, _) = match cats.get(&cat_str) {
            Some(v) => v,
            None => panic!("invalid category {}", cat.to_string()),
        };

        let field_ts = struct_fields
            .entry(cat_str.clone())
            .or_insert_with(|| TokenStream::new());
        let init_ts = struct_inits
            .entry(cat_str.clone())
            .or_insert_with(|| TokenStream::new());

        if cat == "instance" {
            init = quote::quote! {lyquid::runtime::RwLock::new(#init)};
            type_ = quote::quote! {lyquid::runtime::RwLock<#type_>};
        }

        var_setup.extend([quote::quote! {
            // the pointer (only need to do it once, upon initialization of the instance's
            // LiteMemory)
            let ptr: *mut (#type_) = Box::leak(Box::new_in(#init, #cat_alloc));
            let bytes = (ptr as u64).to_be_bytes();
            pa.set(#cat_value, #name_str.as_bytes(), &bytes).expect(FAIL_WRITE_STATE);
        }]);

        field_ts.extend([quote::quote! {
            pub #name: &'static mut (#type_),
        }]);

        init_ts.extend([quote::quote! {
            #name: {
                // retrieve the pointer for Box<T>
                let bytes = pa.get(#cat_value, &#name_str.as_bytes())?.ok_or(lyquid::LyquidError::Init)?;
                let addr = u64::from_be_bytes(bytes.try_into().map_err(|_| lyquid::LyquidError::Init)?);
                unsafe { &mut *(addr as *mut (#type_)) }
            },
        }]);
    }

    var_setup.extend(
        [quote::quote! {
            // the pointer (only need to do it once, upon initialization of the instance's
            // LiteMemory)
            let ptr: *mut lyquid::runtime::internal::BuiltinNetworkState = Box::leak(Box::new_in(lyquid::runtime::internal::BuiltinNetworkState::new(), lyquid::runtime::NetworkAlloc));
            let bytes = (ptr as u64).to_be_bytes();
            internal_pa.set(StateCategory::Network, "network".as_bytes(), &bytes).expect(FAIL_WRITE_STATE);
        }]
    );

    struct_fields
        .entry("network".to_string())
        .or_insert_with(|| TokenStream::new())
        .extend([quote::quote! {
            pub __internal: &'static mut lyquid::runtime::internal::BuiltinNetworkState,
        }]);
    struct_inits
        .entry("network".to_string())
        .or_insert_with(|| TokenStream::new())
        .extend([quote::quote! {
            __internal: {
                // retrieve the pointer for Box<T>
                let bytes = internal_pa.get(StateCategory::Network, "network".as_bytes())?.ok_or(lyquid::LyquidError::Init)?;
                let addr = u64::from_be_bytes(bytes.try_into().map_err(|_| lyquid::LyquidError::Init)?);
                unsafe { &mut *(addr as *mut lyquid::runtime::internal::BuiltinNetworkState) }
            },
        }]);

    // now we summary up each category and generate output
    let mut structs = TokenStream::new();
    for (cat, (_, _, cat_prefix)) in cats.iter() {
        let field_ts = struct_fields.entry(cat.clone()).or_insert_with(|| TokenStream::new());
        let init_ts = struct_inits.entry(cat.clone()).or_insert_with(|| TokenStream::new());
        let sname = quote::format_ident!("{}{}", cat_prefix, struct_suffix);
        structs.extend([quote::quote! {
            pub struct #sname {
                #field_ts
            }

            impl lyquid::runtime::internal::StateAccessor for #sname {
                fn new() -> Result<Self, lyquid::LyquidError> {
                    let internal_pa = lyquid::runtime::internal::PrefixedAccess::new(Vec::from(lyquid::INTERNAL_STATE_PREFIX));
                    let pa = lyquid::runtime::internal::PrefixedAccess::new(Vec::from(lyquid::VAR_CATALOG_PREFIX));
                    Ok(Self {
                        #init_ts
                    })
                }
            }
        }]);
    }
    quote::quote! {
        #structs

        use lyquid::runtime::{oracle, Hash};
        #extra

        #[unsafe(no_mangle)]
        unsafe fn #init_func() {
            const FAIL_WRITE_STATE: &str = "cannot write to low-level state store during LiteMemory initialization";
            let internal_pa = lyquid::runtime::internal::PrefixedAccess::new(Vec::from(lyquid::INTERNAL_STATE_PREFIX));
            let pa = lyquid::runtime::internal::PrefixedAccess::new(Vec::from(lyquid::VAR_CATALOG_PREFIX));
            #var_setup
        }
    }
    .into()
}
