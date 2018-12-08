using System;

namespace org.bouncycastle.Port
{
    public static class JavaSystem
    {
        public static class err
        {
            public static void println(string message)
            {
                Console.Error.WriteLine(message);
            }
        }

        public static class @out
        {
            public static void println()
            {
                Console.WriteLine();
            }

            public static void println(object obj)
            {
                Console.WriteLine(obj);
            }

            public static void println(string message)
            {
                Console.WriteLine(message);
            }

            public static void print(string message)
            {
                Console.Write(message);
            }
        }

        public static void arraycopy<T>(T[] src, int srcPos, T[] dest, int destPos, int length)
        {
            Array.Copy(src, srcPos, dest, destPos, length);
        }

        public static long currentTimeMillis()
        {
            return DateTime.Now.Millisecond;
        }

        public static long nanoTime()
        {
            return DateTime.Now.Ticks;
        }

        public static void exit(int i)
        {
            throw new NotImplementedException();
        }
    }
}
