using System;

namespace org.bouncycastle.Port.Extensions
{
    public static class TypeExtensions
    {
        public static string getName(this Type t)
        {
            return t.FullName;
        }
    }
}
