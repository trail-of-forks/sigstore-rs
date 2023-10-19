// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use const_oid::{AssociatedOid, ObjectIdentifier};

use super::models::VerificationResult;

macro_rules! oids {
    ($($name:ident = $value:literal),+) => {
        $(const $name: ObjectIdentifier = ObjectIdentifier::new_unwrap($value);)+
    };
}

oids! {
    OIDC_ISSUER_OID = "1.3.6.1.4.1.57264.1.1",
    OIDC_GITHUB_WORKFLOW_TRIGGER_OID = "1.3.6.1.4.1.57264.1.2",
    OIDC_GITHUB_WORKFLOW_SHA_OID = "1.3.6.1.4.1.57264.1.3",
    OIDC_GITHUB_WORKFLOW_NAME_OID = "1.3.6.1.4.1.57264.1.4",
    OIDC_GITHUB_WORKFLOW_REPOSITORY_OID = "1.3.6.1.4.1.57264.1.5",
    OIDC_GITHUB_WORKFLOW_REF_OID = "1.3.6.1.4.1.57264.1.6",
    OTHERNAME_OID = "1.3.6.1.4.1.57264.1.7"

}

trait SingleX509ExtPolicy {
    //const OID: [u8] = [];
}

impl<T: SingleX509ExtPolicy> VerificationPolicy for T {
    fn verify(&self, cert: &x509_cert::Certificate) -> VerificationResult {
        todo!()
    }
}

// This would be nice:
/*
impl<T: SingleX509ExtPolicy> AssociatedOid for T {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("s");
}
*/
// But unfortunately it breaks orphan rules.

// TODO(tnytown): Policies.
pub struct OIDCIssuer;
pub struct GitHubWorkflowTrigger;
pub struct GitHubWorkflowSHA;
pub struct GitHubWorkflowName;
pub struct GitHubWorkflowRepository;
pub struct GitHubWorkflowRef;

pub trait VerificationPolicy {
    fn verify(&self, cert: &x509_cert::Certificate) -> VerificationResult;
}

pub struct AnyOf;
pub struct AllOf;
pub struct UnsafeNoOp;

impl VerificationPolicy for UnsafeNoOp {
    fn verify(&self, _cert: &x509_cert::Certificate) -> VerificationResult {
        eprintln!("unsafe (no-op) verification policy used! no verification performed!");
        VerificationResult::Ok(())
    }
}

pub struct Identity;
