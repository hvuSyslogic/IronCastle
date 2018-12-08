namespace org.bouncycastle.crypto.ec
{
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	public class ECPair
	{
		private readonly ECPoint x;
		private readonly ECPoint y;

		public ECPair(ECPoint x, ECPoint y)
		{
			this.x = x;
			this.y = y;
		}

		public virtual ECPoint getX()
		{
			return x;
		}

		public virtual ECPoint getY()
		{
			return y;
		}

		public virtual bool Equals(ECPair other)
		{
			return other.getX().Equals(getX()) && other.getY().Equals(getY());
		}

		public override bool Equals(object other)
		{
			return other is ECPair ? Equals((ECPair)other) : false;
		}

		public override int GetHashCode()
		{
			return x.GetHashCode() + 37 * y.GetHashCode();
		}
	}

}