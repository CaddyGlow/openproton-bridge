use tokio::io::AsyncWriteExt;

use crate::imap_error::ImapResult as Result;

pub struct ResponseWriter<W: AsyncWriteExt + Unpin> {
    writer: W,
}

impl<W: AsyncWriteExt + Unpin> ResponseWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub async fn tagged_ok(&mut self, tag: &str, code: Option<&str>, msg: &str) -> Result<()> {
        let line = match code {
            Some(c) => format!("{} OK [{}] {}\r\n", tag, c, msg),
            None => format!("{} OK {}\r\n", tag, msg),
        };
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn tagged_no(&mut self, tag: &str, msg: &str) -> Result<()> {
        let line = format!("{} NO {}\r\n", tag, msg);
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn tagged_bad(&mut self, tag: &str, msg: &str) -> Result<()> {
        let line = format!("{} BAD {}\r\n", tag, msg);
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn untagged(&mut self, msg: &str) -> Result<()> {
        let line = format!("* {}\r\n", msg);
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn continuation(&mut self, msg: &str) -> Result<()> {
        let line = format!("+ {}\r\n", msg);
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn raw(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data).await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.writer.flush().await?;
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tagged_ok() {
        let mut buf = Vec::new();
        {
            let mut w = ResponseWriter::new(&mut buf);
            w.tagged_ok("a001", None, "completed").await.unwrap();
        }
        assert_eq!(buf, b"a001 OK completed\r\n");
    }

    #[tokio::test]
    async fn test_tagged_ok_with_code() {
        let mut buf = Vec::new();
        {
            let mut w = ResponseWriter::new(&mut buf);
            w.tagged_ok("a001", Some("READ-WRITE"), "SELECT completed")
                .await
                .unwrap();
        }
        assert_eq!(buf, b"a001 OK [READ-WRITE] SELECT completed\r\n");
    }

    #[tokio::test]
    async fn test_tagged_no() {
        let mut buf = Vec::new();
        {
            let mut w = ResponseWriter::new(&mut buf);
            w.tagged_no("a002", "FETCH failed").await.unwrap();
        }
        assert_eq!(buf, b"a002 NO FETCH failed\r\n");
    }

    #[tokio::test]
    async fn test_tagged_bad() {
        let mut buf = Vec::new();
        {
            let mut w = ResponseWriter::new(&mut buf);
            w.tagged_bad("a003", "syntax error").await.unwrap();
        }
        assert_eq!(buf, b"a003 BAD syntax error\r\n");
    }

    #[tokio::test]
    async fn test_untagged() {
        let mut buf = Vec::new();
        {
            let mut w = ResponseWriter::new(&mut buf);
            w.untagged("42 EXISTS").await.unwrap();
        }
        assert_eq!(buf, b"* 42 EXISTS\r\n");
    }

    #[tokio::test]
    async fn test_continuation() {
        let mut buf = Vec::new();
        {
            let mut w = ResponseWriter::new(&mut buf);
            w.continuation("ready").await.unwrap();
        }
        assert_eq!(buf, b"+ ready\r\n");
    }

    #[tokio::test]
    async fn test_raw() {
        let mut buf = Vec::new();
        {
            let mut w = ResponseWriter::new(&mut buf);
            w.raw(b"literal data here").await.unwrap();
        }
        assert_eq!(buf, b"literal data here");
    }
}
