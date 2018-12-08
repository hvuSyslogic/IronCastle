using System;
using System.Collections.Generic;
using System.Text;

namespace BouncyCastle.Core.Port.java.lang
{
    public interface Cloneable
    {
        object clone();
    }

    public interface Cloneable<T>
    {
        T clone();
    }
}
