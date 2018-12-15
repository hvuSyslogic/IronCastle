using System;
using System.Collections.Generic;
using System.Text;
using org.bouncycastle.Port.java.util;
using Random = System.Random;

namespace BouncyCastle.Core.Port
{
    public class BigInteger
    {
        public static BigInteger ZERO = valueOf(0);
        public static BigInteger ONE = valueOf(1);

        public BigInteger(string v1)
        {
            throw new NotImplementedException();
        }

        public BigInteger(int v, byte[] m)
        {
            throw new NotImplementedException();
        }

        public BigInteger(byte[] bytes)
        {
            throw new NotImplementedException();
        }

        public BigInteger(string val, int i)
        {
            throw new NotImplementedException();
        }

        public BigInteger(int m, org.bouncycastle.Port.java.util.Random rand)
        {
        }

        public BigInteger(int bytes, Random rand)
        {
            throw new NotImplementedException();
        }

        public BigInteger(int bytes, SecureRandom rand)
        {
            throw new NotImplementedException();
        }

        public static BigInteger valueOf(long input)
        {
            throw new NotImplementedException();
        }

        public int CompareTo(BigInteger other)
        {
            throw new NotImplementedException();
        }

        public BigInteger divide(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public static BigInteger operator +(BigInteger a, BigInteger b)
        {
            throw new NotImplementedException();
        }

        public static BigInteger operator -(BigInteger a, BigInteger b)
        {
            throw new NotImplementedException();
        }

        public static BigInteger operator *(BigInteger a, BigInteger b)
        {
            throw new NotImplementedException();
        }

        public static BigInteger operator >>(BigInteger a, int b)
        {
            throw new NotImplementedException();
        }

        public string ToString(int v)
        {
            throw new NotImplementedException();
        }

        public static BigInteger operator <<(BigInteger a, int b)
        {
            throw new NotImplementedException();
        }

        public static BigInteger operator %(BigInteger a, int b)
        {
            throw new NotImplementedException();
        }

        public static BigInteger operator %(BigInteger a, BigInteger b)
        {
            throw new NotImplementedException();
        }

        public byte[] ToByteArray()
        {
            throw new NotImplementedException();

        }

        public BigInteger modPow(BigInteger privateValue, BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public BigInteger multiply(BigInteger result)
        {
            throw new NotImplementedException();
        }

        public BigInteger mod(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public int bitLength()
        {
            throw new NotImplementedException();
        }

        public BigInteger setBit(int i)
        {
            throw new NotImplementedException();
        }

        public BigInteger add(BigInteger getD)
        {
            throw new NotImplementedException();
        }

        public int compareTo(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public int intValue()
        {
            throw new NotImplementedException();
        }

        public byte[] toByteArray()
        {
            throw new NotImplementedException();
        }

        public BigInteger or(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public BigInteger subtract(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public BigInteger shiftLeft(int i)
        {
            throw new NotImplementedException();
        }

        public BigInteger shiftRight(int i)
        {
            throw new NotImplementedException();
        }

        public bool isProbablePrime(int i)
        {
            throw new NotImplementedException();
        }

        public BigInteger negate()
        {
            throw new NotImplementedException();
        }

        public BigInteger pow(int i)
        {
            throw new NotImplementedException();
        }

        public BigInteger and(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public BigInteger modInverse(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public BigInteger remainder(BigInteger p0)
        {
            throw new NotImplementedException();
        }

        public int signum()
        {
            throw new NotImplementedException();
        }

        public long longValue()
        {
            throw new NotImplementedException();
        }

        public BigInteger gcd(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public BigInteger abs()
        {
            throw new NotImplementedException();
        }

        public BigInteger max(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public bool testBit(int i)
        {
            throw new NotImplementedException();
        }

        public BigInteger min(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public int getLowestSetBit()
        {
            throw new NotImplementedException();
        }

        public BigInteger clearBit(int i)
        {
            throw new NotImplementedException();
        }

        public BigInteger[] divideAndRemainder(BigInteger r1)
        {
            throw new NotImplementedException();
        }

        public BigInteger xor(BigInteger bigInteger)
        {
            throw new NotImplementedException();
        }

        public int bitCount()
        {
            throw new NotImplementedException();
        }

        public byte byteValue()
        {
            throw new NotImplementedException();
        }
    }
}
