﻿using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.crypto.ec;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.math.ec.tools
{

				
	public class TraceOptimizer
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private static readonly SecureRandom R = new SecureRandom();

		public static void Main(string[] args)
		{
			SortedSet names = new TreeSet(enumToList(ECNamedCurveTable.getNames()));
			names.addAll(enumToList(CustomNamedCurves.getNames()));

			Iterator it = names.iterator();
			while (it.hasNext())
			{
				string name = (string)it.next();
				X9ECParameters x9 = CustomNamedCurves.getByName(name);
				if (x9 == null)
				{
					x9 = ECNamedCurveTable.getByName(name);
				}
				if (x9 != null && ECAlgorithms.isF2mCurve(x9.getCurve()))
				{
					JavaSystem.@out.print(name + ":");
					implPrintNonZeroTraceBits(x9);
				}
			}
		}

		public static void printNonZeroTraceBits(X9ECParameters x9)
		{
			if (!ECAlgorithms.isF2mCurve(x9.getCurve()))
			{
				throw new IllegalArgumentException("Trace only defined over characteristic-2 fields");
			}

			implPrintNonZeroTraceBits(x9);
		}

		public static void implPrintNonZeroTraceBits(X9ECParameters x9)
		{
			ECCurve c = x9.getCurve();
			int m = c.getFieldSize();

			ArrayList nonZeroTraceBits = new ArrayList();

			/*
			 * Determine which of the bits contribute to the trace.
			 * 
			 * See section 3.6.2 of "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone)
			 */
			{
				for (int i = 0; i < m; ++i)
				{
					BigInteger zi = ONE.shiftLeft(i);
					ECFieldElement fe = c.fromBigInteger(zi);
					int tr = calculateTrace(fe);
					if (tr != 0)
					{
						nonZeroTraceBits.add(Integers.valueOf(i));
						JavaSystem.@out.print(" " + i);
					}
				}
				JavaSystem.@out.println();
			}

			/*
			 *  Check calculation based on the non-zero-trace bits against explicit calculation, for random field elements
			 */
			{
				for (int i = 0; i < 1000; ++i)
				{
					BigInteger x = new BigInteger(m, R);
					ECFieldElement fe = c.fromBigInteger(x);
					int check = calculateTrace(fe);

					int tr = 0;
					for (int j = 0; j < nonZeroTraceBits.size(); ++j)
					{
						int bit = ((int?)nonZeroTraceBits.get(j)).Value;
						if (x.testBit(bit))
						{
							tr ^= 1;
						}
					}

					if (check != tr)
					{
						throw new IllegalStateException("Optimized-trace sanity check failed");
					}
				}
			}
		}

		private static int calculateTrace(ECFieldElement fe)
		{
			int m = fe.getFieldSize();
			ECFieldElement tr = fe;
			for (int i = 1; i < m; ++i)
			{
				fe = fe.square();
				tr = tr.add(fe);
			}
			BigInteger b = tr.toBigInteger();
			if (b.bitLength() > 1)
			{
				throw new IllegalStateException();
			}
			return b.intValue();
		}

		private static ArrayList enumToList(Enumeration en)
		{
			ArrayList rv = new ArrayList();
			while (en.hasMoreElements())
			{
				rv.add(en.nextElement());
			}
			return rv;
		}
	}

}