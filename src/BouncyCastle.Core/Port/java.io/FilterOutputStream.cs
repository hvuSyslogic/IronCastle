namespace org.bouncycastle.Port.java.io
{
    public class FilterOutputStream : OutputStream
    {
        protected internal OutputStream @out;

        protected internal FilterOutputStream(OutputStream underlying)
        {
            @out = underlying;
        }

        public override void write(int tag)
        {
            @out.write(tag);
        }

        public override void write(byte[] bytes)
        {
            @out.write(bytes);
        }

        public override void write(byte[] result, int pos, int v)
        {
            @out.write(result, pos, v);
        }

        public override void flush()
        {
            @out.flush();
        }

        public override void close()
        {
            @out.close();
        }

        public override int size()
        {
            return @out.size();
        }
    }
}
