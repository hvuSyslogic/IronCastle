using BouncyCastle.Core.Port;
using org.bouncycastle.math.ec;

namespace org.bouncycastle.math.ec.endo
{


	public class GLVTypeBEndomorphism : GLVEndomorphism
	{
		protected internal readonly ECCurve curve;
		protected internal readonly GLVTypeBParameters parameters;
		protected internal readonly ECPointMap pointMap;

		public GLVTypeBEndomorphism(ECCurve curve, GLVTypeBParameters parameters)
		{
			this.curve = curve;
			this.parameters = parameters;
			this.pointMap = new ScaleXPointMap(curve.fromBigInteger(parameters.getBeta()));
		}

		public virtual BigInteger[] decomposeScalar(BigInteger k)
		{
			int bits = parameters.getBits();
			BigInteger b1 = calculateB(k, parameters.getG1(), bits);
			BigInteger b2 = calculateB(k, parameters.getG2(), bits);

			GLVTypeBParameters p = parameters;
			BigInteger a = k.subtract((b1.multiply(p.getV1A())).add(b2.multiply(p.getV2A())));
			BigInteger b = (b1.multiply(p.getV1B())).add(b2.multiply(p.getV2B())).negate();

			return new BigInteger[]{a, b};
		}

		public virtual ECPointMap getPointMap()
		{
			return pointMap;
		}

		public virtual bool hasEfficientPointMap()
		{
			return true;
		}

		public virtual BigInteger calculateB(BigInteger k, BigInteger g, int t)
		{
			bool negative = (g.signum() < 0);
			BigInteger b = k.multiply(g.abs());
			bool extra = b.testBit(t - 1);
			b = b.shiftRight(t);
			if (extra)
			{
				b = b.add(ECConstants_Fields.ONE);
			}
			return negative ? b.negate() : b;
		}
	}

}