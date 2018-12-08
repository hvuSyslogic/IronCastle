using System;
using System.Collections.Generic;
using System.Text;

namespace BouncyCastle.Core.Port
{
    public interface IEnumerator
    {
        bool hasMoreElements();
        object nextElement();
    }

    public interface IEnumerator<T>
    {
        bool hasMoreElements();
        T nextElement();
    }
}
