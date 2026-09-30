use core::{convert::Infallible, fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// Represents the type of runtime environment that this Tailscale node is running in/on.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum EnvType {
    /// Unknown environment.
    #[default]
    Unknown,
    /// Running on knative.
    KNative,
    /// Running on AWS lambda.
    AWSLambda,
    /// Running on Heroku.
    Heroku,
    /// Running on Azure App Service.
    AzureAppService,
    /// Running on AWS Fargate.
    AWSFargate,
    /// Running on fly.io.
    FlyDotIo,
    /// Running in kubernetes.
    Kubernetes,
    /// Running in Docker Desktop.
    DockerDesktop,
    /// Running on repl.it.
    Replit,
    /// Running in the Home Assistant addon.
    HomeAssistantAddOn,
}

impl fmt::Display for EnvType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            EnvType::Unknown => "",
            EnvType::KNative => "kn",
            EnvType::AWSLambda => "lm",
            EnvType::Heroku => "hr",
            EnvType::AzureAppService => "az",
            EnvType::AWSFargate => "fg",
            EnvType::FlyDotIo => "fly",
            EnvType::Kubernetes => "k8s",
            EnvType::DockerDesktop => "dde",
            EnvType::Replit => "repl",
            EnvType::HomeAssistantAddOn => "haao",
        };
        write!(f, "{str}")
    }
}

impl FromStr for EnvType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = match s {
            "kn" => Self::KNative,
            "lm" => Self::AWSLambda,
            "hr" => Self::Heroku,
            "az" => Self::AzureAppService,
            "fg" => Self::AWSFargate,
            "fly" => Self::FlyDotIo,
            "k8s" => Self::Kubernetes,
            "dde" => Self::DockerDesktop,
            "repl" => Self::Replit,
            "haao" => Self::HomeAssistantAddOn,
            _ => Self::Unknown,
        };
        Ok(value)
    }
}
