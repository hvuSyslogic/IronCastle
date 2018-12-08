namespace org.bouncycastle.Port
{
    public class Runtime
    {
        public static Runtime getRuntime()
        {
            return new Runtime();
        }

        //NOTE: This is just static for the moment
        public long maxMemory()
        {
            return 1024 * 1024 * 1024;
        }

        //NOTE: This is just static for the moment
        public long totalMemory()
        {
            return 1024 * 1024;
        }
    }
}
