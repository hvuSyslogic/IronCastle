using System;
using System.Collections.Generic;
using System.Text;
using DateTime = BouncyCastle.Core.Port.java.text.DateTime;

namespace BouncyCastle.Core.Port.java.util
{
    public class TimeZone
    {
        public static TimeZone getDefault()
        {
            throw new NotImplementedException();
        }

        public int getRawOffset()
        {
            throw new NotImplementedException();
        }

        public bool useDaylightTime()
        {
            throw new NotImplementedException();
        }

        public bool inDaylightTime(DateTime getDate)
        {
            throw new NotImplementedException();
        }

        public string getID()
        {
            throw new NotImplementedException();
        }
    }
}
