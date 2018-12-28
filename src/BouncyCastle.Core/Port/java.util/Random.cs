namespace org.bouncycastle.Port.java.util
{
    public class Random
    {
        System.Random _r;

        public Random()
        {
            _r = new System.Random();
        }

        public Random(int seed)
        {
            _r = new System.Random(seed);
        }

        public virtual int nextInt()
        {
            return _r.Next();
        }

        public virtual long nextLong()
        {
            return (long)_r.NextDouble();
        }
    }
}
