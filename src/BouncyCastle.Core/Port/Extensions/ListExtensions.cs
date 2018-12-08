using System;
using System.Collections;
using System.Collections.Generic;

namespace BouncyCastle.Core.Port.Extensions
{
    public static class ListExtensions
    {
        public static IEnumerator elements(this List<object> list)
        {
            return list.GetEnumerator();
        }
    }
}
