use mail_send::Credentials;
use smtp_proto::{
    request::{parser::Rfc5321Parser, AUTH},
    response::generate::BitToString,
    IntoString, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ImapClient, ImapError};

impl<T: AsyncRead + AsyncWrite + Unpin> ImapClient<T> {
    pub async fn authenticate(
        &mut self,
        mechanism: u64,
        credentials: &Credentials<String>,
    ) -> Result<(), ImapError> {
        if (mechanism & (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER)) != 0 {
            self.write(
                format!(
                    "C3 AUTHENTICATE {} {}\r\n",
                    mechanism.to_mechanism(),
                    credentials
                        .encode(mechanism, "")
                        .map_err(|err| ImapError::InvalidChallenge(err.to_string()))?
                )
                .as_bytes(),
            )
            .await?;
        } else {
            self.write(format!("C3 AUTHENTICATE {}\r\n", mechanism.to_mechanism()).as_bytes())
                .await?;
        }
        let mut line = self.read_line().await?;

        for _ in 0..3 {
            if matches!(line.first(), Some(b'+')) {
                self.write(
                    format!(
                        "{}\r\n",
                        credentials
                            .encode(
                                mechanism,
                                std::str::from_utf8(line.get(2..).unwrap_or_default())
                                    .unwrap_or_default()
                            )
                            .map_err(|err| ImapError::InvalidChallenge(err.to_string()))?
                    )
                    .as_bytes(),
                )
                .await?;
                line = self.read_line().await?;
            } else if matches!(line.get(..5), Some(b"C3 OK")) {
                return Ok(());
            } else if matches!(line.get(..5), Some(b"C3 NO"))
                || matches!(line.get(..6), Some(b"C3 BAD"))
            {
                return Err(ImapError::AuthenticationFailed);
            } else {
                return Err(ImapError::InvalidResponse(line.into_string()));
            }
        }

        Err(ImapError::InvalidResponse(line.into_string()))
    }

    pub async fn authentication_mechanisms(&mut self) -> Result<u64, ImapError> {
        tokio::time::timeout(self.timeout, async {
            self.write(b"C0 CAPABILITY\r\n").await?;

            let line = self.read_line().await?;
            if !matches!(line.get(..12), Some(b"* CAPABILITY")) {
                return Err(ImapError::InvalidResponse(line.into_string()));
            }

            let mut line_iter = line.iter();
            let mut parser = Rfc5321Parser::new(&mut line_iter);
            let mut mechanisms = 0;

            'outer: while let Ok(ch) = parser.read_char() {
                if ch == b' ' {
                    loop {
                        if parser.hashed_value().unwrap_or(0) == AUTH && parser.stop_char == b'=' {
                            if let Ok(Some(mechanism)) = parser.mechanism() {
                                mechanisms |= mechanism;
                            }
                            match parser.stop_char {
                                b' ' => (),
                                b'\n' => break 'outer,
                                _ => break,
                            }
                        }
                    }
                } else if ch == b'\n' {
                    break;
                }
            }

            Ok(mechanisms)
        })
        .await
        .map_err(|_| ImapError::Timeout)?
    }

    pub async fn noop(&mut self) -> Result<(), ImapError> {
        tokio::time::timeout(self.timeout, async {
            self.write(b"C8 NOOP\r\n").await?;
            self.read_line().await?;
            Ok(())
        })
        .await
        .map_err(|_| ImapError::Timeout)?
    }

    pub async fn logout(&mut self) -> Result<(), ImapError> {
        tokio::time::timeout(self.timeout, async {
            self.write(b"C9 LOGOUT\r\n").await?;
            Ok(())
        })
        .await
        .map_err(|_| ImapError::Timeout)?
    }

    pub async fn expect_greeting(&mut self) -> Result<(), ImapError> {
        tokio::time::timeout(self.timeout, async {
            let line = self.read_line().await?;
            if matches!(line.get(..4), Some(b"* OK")) {
                Ok(())
            } else {
                Err(ImapError::InvalidResponse(line.into_string()))
            }
        })
        .await
        .map_err(|_| ImapError::Timeout)?
    }

    pub async fn read_line(&mut self) -> Result<Vec<u8>, ImapError> {
        let mut buf = vec![0u8; 1024];
        let mut buf_extended = Vec::with_capacity(0);

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                if matches!(buf.get(br - 1), Some(b'\n')) {
                    //println!("{:?}", std::str::from_utf8(&buf[..br]).unwrap());
                    return Ok(if buf_extended.is_empty() {
                        buf.truncate(br);
                        buf
                    } else {
                        buf_extended.extend_from_slice(&buf[..br]);
                        buf_extended
                    });
                } else if buf_extended.is_empty() {
                    buf_extended = buf[..br].to_vec();
                } else {
                    buf_extended.extend_from_slice(&buf[..br]);
                }
            } else {
                return Err(ImapError::Disconnected);
            }
        }
    }

    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }
}
