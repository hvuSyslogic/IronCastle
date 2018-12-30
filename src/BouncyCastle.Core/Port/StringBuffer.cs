using System.Text;

namespace org.bouncycastle.Port
{
    public class StringBuffer
    {
        private readonly StringBuilder _innerBuilder;

        public StringBuffer()
        {
            _innerBuilder = new StringBuilder();
        }

        public StringBuffer(int capacity)
        {
            _innerBuilder = new StringBuilder(capacity);
        }

        public StringBuffer(string v)
        {
            _innerBuilder = new StringBuilder(v);
        }

        public StringBuffer append(char c)
        {
            _innerBuilder.Append(c);
            return this;
        }

        public StringBuffer append(string v)
        {
            _innerBuilder.Append(v);
            return this;
        }

        public StringBuffer append(object o)
        {
            _innerBuilder.Append(o.ToString());
            return this;
        }

        public void setLength(int i)
        {
            _innerBuilder.Length = i;
        }

        public int length()
        {
            return _innerBuilder.Length;
        }

        public char charAt(int i)
        {
            return _innerBuilder[i];
        }

        public StringBuffer insert(int index, string p1)
        {
           return new StringBuffer(_innerBuilder.Insert(index, p1).ToString());
        }

        public void insert(int index, char value)
        {
            _innerBuilder.Insert(index, value);
        }

        public void replace(int p0, int p1, string p2)
        {
            throw new System.NotImplementedException();
        }
    }
}
