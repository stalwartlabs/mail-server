/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use crate::{
    responses::XmlEscape,
    schema::{
        property::{DavProperty, Privilege},
        response::{
            Ace, AclRestrictions, GrantDeny, Href, List, Principal, PrincipalSearchProperty,
            PrincipalSearchPropertySet, RequiredPrincipal, Resource, SupportedPrivilege,
        },
        Namespace, Namespaces,
    },
};

impl Display for SupportedPrivilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:supported-privilege>{}", self.privilege)?;
        if self.abstract_ {
            write!(f, "<D:abstract/>")?;
        }
        write!(f, "<D:description>")?;
        self.description.write_escaped_to(f)?;
        write!(
            f,
            "</D:description>{}</D:supported-privilege>",
            self.supported_privilege
        )
    }
}

impl SupportedPrivilege {
    pub fn new(privilege: Privilege, description: impl Into<String>) -> Self {
        SupportedPrivilege {
            privilege,
            abstract_: false,
            description: description.into(),
            supported_privilege: List(vec![]),
        }
    }

    pub fn with_abstract(mut self) -> Self {
        self.abstract_ = true;
        self
    }

    pub fn with_supported_privilege(mut self, supported_privilege: SupportedPrivilege) -> Self {
        self.supported_privilege.0.push(supported_privilege);
        self
    }

    pub fn with_opt_supported_privilege(
        mut self,
        supported_privilege: Option<SupportedPrivilege>,
    ) -> Self {
        if let Some(supported_privilege) = supported_privilege {
            self.supported_privilege.0.push(supported_privilege);
        }
        self
    }
}

impl Display for Ace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:ace>")?;
        if self.invert {
            write!(f, "<D:invert>")?;
        }
        self.principal.fmt(f)?;
        if self.invert {
            write!(f, "</D:invert>")?;
        }
        self.grant_deny.fmt(f)?;
        if self.protected {
            write!(f, "<D:protected/>")?;
        }
        if let Some(inherited) = &self.inherited {
            write!(f, "<D:inherited>")?;
            inherited.fmt(f)?;
            write!(f, "</D:inherited>")?;
        }
        write!(f, "</D:ace>")
    }
}

impl Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:principal>")?;
        match self {
            Principal::Href(href) => href.fmt(f),
            Principal::Response(response) => response.fmt(f),
            Principal::All => "<D:all/>".fmt(f),
            Principal::Authenticated => "<D:authenticated/>".fmt(f),
            Principal::Unauthenticated => "<D:unauthenticated/>".fmt(f),
            Principal::Property(property) => {
                write!(f, "<D:property>{}</D:property>", property)
            }
            Principal::Self_ => "<D:self/>".fmt(f),
        }?;
        write!(f, "</D:principal>")
    }
}

impl Display for GrantDeny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantDeny::Grant(privileges) => {
                write!(f, "<D:grant>")?;
                privileges.fmt(f)?;
                write!(f, "</D:grant>")
            }
            GrantDeny::Deny(privileges) => {
                write!(f, "<D:deny>")?;
                privileges.fmt(f)?;
                write!(f, "</D:deny>")
            }
        }
    }
}

impl Display for AclRestrictions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.grant_only {
            write!(f, "<D:grant-only/>")?;
        }
        if self.no_invert {
            write!(f, "<D:no-invert/>")?;
        }
        if self.deny_before_grant {
            write!(f, "<D:deny-before-grant/>")?;
        }
        if let Some(required_principal) = &self.required_principal {
            required_principal.fmt(f)?;
        }
        Ok(())
    }
}

impl Display for RequiredPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<D:required-principal>")?;
        match self {
            RequiredPrincipal::All => "<D:all/>".fmt(f)?,
            RequiredPrincipal::Authenticated => "<D:authenticated/>".fmt(f)?,
            RequiredPrincipal::Unauthenticated => "<D:unauthenticated/>".fmt(f)?,
            RequiredPrincipal::Self_ => "<D:self/>".fmt(f)?,
            RequiredPrincipal::Href(hrefs) => hrefs.fmt(f)?,
            RequiredPrincipal::Property(properties) => {
                for property in properties {
                    write!(f, "<D:property>{}</D:property>", property)?;
                }
            }
        }
        write!(f, "</D:required-principal>")
    }
}

impl Display for Privilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Privilege::Read => "<D:privilege><D:read/></D:privilege>".fmt(f),
            Privilege::Write => "<D:privilege><D:write/></D:privilege>".fmt(f),
            Privilege::WriteProperties => "<D:privilege><D:write-properties/></D:privilege>".fmt(f),
            Privilege::WriteContent => "<D:privilege><D:write-content/></D:privilege>".fmt(f),
            Privilege::Unlock => "<D:privilege><D:unlock/></D:privilege>".fmt(f),
            Privilege::ReadAcl => "<D:privilege><D:read-acl/></D:privilege>".fmt(f),
            Privilege::ReadCurrentUserPrivilegeSet => {
                "<D:privilege><D:read-current-user-privilege-set/></D:privilege>".fmt(f)
            }
            Privilege::WriteAcl => "<D:privilege><D:write-acl/></D:privilege>".fmt(f),
            Privilege::Bind => "<D:privilege><D:bind/></D:privilege>".fmt(f),
            Privilege::Unbind => "<D:privilege><D:unbind/></D:privilege>".fmt(f),
            Privilege::All => "<D:privilege><D:all/></D:privilege>".fmt(f),
            Privilege::ReadFreeBusy => "<D:privilege><A:read-free-busy/></D:privilege>".fmt(f),
        }
    }
}

impl Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<D:resource>{}{}</D:resource>",
            self.href, self.privilege
        )
    }
}

impl Display for PrincipalSearchPropertySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        write!(
            f,
            "<D:principal-search-property-set {}>{}</D:principal-search-property-set>",
            self.namespaces, self.properties
        )
    }
}

impl Display for PrincipalSearchProperty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<D:principal-search-property><D:prop>{}</D:prop>",
            self.name
        )?;
        write!(
            f,
            "<D:description>{}</D:description></D:principal-search-property>",
            self.description
        )
    }
}

impl Resource {
    pub fn new(href: impl Into<String>, privilege: Privilege) -> Self {
        Resource {
            href: Href(href.into()),
            privilege,
        }
    }
}

impl PrincipalSearchPropertySet {
    pub fn new(properties: Vec<PrincipalSearchProperty>) -> Self {
        PrincipalSearchPropertySet {
            namespaces: Namespaces::default(),
            properties: List(properties),
        }
    }

    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.namespaces.set(namespace);
        self
    }
}

impl PrincipalSearchProperty {
    pub fn new(name: impl Into<DavProperty>, description: impl Into<String>) -> Self {
        PrincipalSearchProperty {
            name: name.into(),
            description: description.into(),
        }
    }
}

impl Ace {
    pub fn new(principal: Principal, grant_deny: GrantDeny) -> Self {
        Ace {
            principal,
            invert: false,
            grant_deny,
            protected: false,
            inherited: None,
        }
    }

    pub fn with_invert(mut self) -> Self {
        self.invert = true;
        self
    }

    pub fn with_protected(mut self) -> Self {
        self.protected = true;
        self
    }

    pub fn with_inherited(mut self, inherited: impl Into<String>) -> Self {
        self.inherited = Some(Href(inherited.into()));
        self
    }
}

impl GrantDeny {
    pub fn grant(privileges: Vec<Privilege>) -> Self {
        GrantDeny::Grant(List(privileges))
    }

    pub fn deny(privileges: Vec<Privilege>) -> Self {
        GrantDeny::Deny(List(privileges))
    }
}

impl AclRestrictions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_grant_only(mut self) -> Self {
        self.grant_only = true;
        self
    }

    pub fn with_no_invert(mut self) -> Self {
        self.no_invert = true;
        self
    }

    pub fn with_deny_before_grant(mut self) -> Self {
        self.deny_before_grant = true;
        self
    }

    pub fn with_required_principal(mut self, required_principal: RequiredPrincipal) -> Self {
        self.required_principal = Some(required_principal);
        self
    }
}
