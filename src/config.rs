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

use cloud_util::{common::read_toml, tracer::LogConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub master_key: String,
    pub log_config: LogConfig,
}

impl Config {
    pub fn new(config_str: &str) -> Self {
        read_toml(config_str, "cloud_kms")
    }
}
