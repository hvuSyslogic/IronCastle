using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.math.ec.tools
{

	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;

	public class F2mSqrtOptimizer
	{
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
					implPrintRootZ(x9);
				}
			}
		}

		public static void printRootZ(X9ECParameters x9)
		{
			if (!ECAlgorithms.isF2mCurve(x9.getCurve()))
			{
				throw new IllegalArgumentException("Sqrt optimization only defined over characteristic-2 fields");
			}

			implPrintRootZ(x9);
		}

		private static void implPrintRootZ(X9ECParameters x9)
		{
			ECFieldElement z = x9.getCurve().fromBigInteger(BigInteger.valueOf(2));
			ECFieldElement rootZ = z.sqrt();

			JavaSystem.@out.println(rootZ.toBigInteger().ToString(16).ToUpper());

			if (!rootZ.square().Equals(z))
			{
				throw new IllegalStateException("Optimized-sqrt sanity check failed");
			}
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