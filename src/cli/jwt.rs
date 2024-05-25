use clap::Parser;
use enum_dispatch::enum_dispatch;
use crate::{CmdExector};


#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JwtSubCommand {
    Sign(JwtSignOpts),
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(short, long, default_value = "")]
    pub sub: String,
    #[arg(short, long, default_value = "")]
    pub aud: String,
    #[arg(short, long, default_value_t = 0)]
    pub exp: i64,
    #[arg(short, long, default_value_t = 0)]
    pub iat: i64,
    #[arg(short, long, default_value = "")]
    pub name: String,
    #[arg(long)]
    pub secret_key: String,
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(short, long)]
    pub token: String,
    #[arg(long)]
    pub secret_key: String,
}

impl CmdExector for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let claims = crate::Claims {
            aud: self.aud,
            exp: self.exp as usize, // Cast i64 to usize, ensure this does not lead to underflow/overflow
            iat: self.iat as usize, // Cast i64 to usize
            iss: self.name,
            nbf: self.iat as usize, // Optionally, set this to a specific value if required
            sub: self.sub,
        };

        let token = crate::process_jwt_sign(&self.secret_key, claims)?;

        println!("{}", token);

        Ok(())
    }
}

impl CmdExector for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let claims = crate::process_jwt_verify(&self.token, &self.secret_key)?;

        println!("{:#?}", claims);
        Ok(())
    }
}