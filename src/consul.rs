// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::Result;
use rs_consul::{
    Consul, RegisterEntityCheck, RegisterEntityPayload, RegisterEntityService, ResponseMeta,
};

use crate::config::Config;

pub async fn register_service(consul: &Consul, config: &Config) -> Result<()> {
    let payload = RegisterEntityPayload {
        ID: None,
        Node: "LOCAL".to_string(),
        Address: "127.0.0.1".to_string(),
        Datacenter: None,
        TaggedAddresses: Default::default(),
        NodeMeta: Default::default(),
        Service: Some(RegisterEntityService {
            ID: Some(config.service_name.clone()),
            Service: config.service_name.clone(),
            Tags: vec![],
            TaggedAddresses: Default::default(),
            Meta: Default::default(),
            Port: Some(config.port),
            Namespace: None,
        }),
        Check: Some(RegisterEntityCheck {
            Node: None,
            CheckID: None,
            Name: config.service_name.clone(),
            Notes: None,
            Status: Some("passing".to_string()),
            ServiceID: Some(config.service_name.clone()),
            Definition: Default::default(),
        }),
        SkipNodeUpdate: None,
    };
    consul.register_entity(&payload).await.map_err(|e| {
        anyhow::Error::msg(format!(
            "register service({}) failed: {:?}",
            config.service_name, e
        ))
    })?;

    // verify the newly registered service is retrieved
    let ResponseMeta {
        response: service_names_after_register,
        ..
    } = consul
        .get_all_registered_service_names(None)
        .await
        .map_err(|e| {
            anyhow::Error::msg(format!(
                "register service({}) failed: {:?}",
                config.service_name, e
            ))
        })?;
    if service_names_after_register.contains(&config.service_name) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "register service({}) failed: service not found",
            config.service_name
        ))
    }
}
