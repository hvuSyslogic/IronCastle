using System;
using org.bouncycastle.Port.java.nio.channels;

namespace org.bouncycastle.Port.java.io
{
    public class FileInputStream : InputStream
    {
        private string v;

        public FileInputStream(string v)
        {
            this.v = v;
        }

        public FileChannel getChannel()
        {
            throw new NotImplementedException();
        }
    }

    public class FileOutputStream : OutputStream
    {
        private string outfile;

        public FileOutputStream(string outfile)
        {
            this.outfile = outfile;
        }
    }
}
