using System;
using System.Collections.Generic;
using System.Text;

namespace BouncyCastle.Core.Port.java.lang
{
    public class BigDecimal
    {
        private string v;
        public static bool ROUND_HALF_EVEN;

        public BigDecimal(string v)
        {
            this.v = v;
        }

        public BigDecimal(BigInteger pCoeff)
        {
            throw new NotImplementedException();
        }

        public BigDecimal multiply(BigDecimal oneHalf)
        {
            throw new NotImplementedException();
        }

        public BigDecimal add(BigDecimal cCoeff)
        {
            throw new NotImplementedException();
        }

        public BigDecimal subtract(BigDecimal bCoeff)
        {
            throw new NotImplementedException();
        }

        public BigDecimal setScale(int i, bool roundHalfEven)
        {
            throw new NotImplementedException();
        }

        public BigInteger toBigInteger()
        {
            throw new NotImplementedException();


        }

        public static BigDecimal valueOf(int i)
        {
            throw new NotImplementedException();
        }

        public BigDecimal divide(BigDecimal divisor, int i, bool roundHalfEven)
        {
            throw new NotImplementedException();
        }
    }
}
