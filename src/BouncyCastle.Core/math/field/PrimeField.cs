using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.field
{

	public class PrimeField : FiniteField
	{
		protected internal readonly BigInteger characteristic;

		public PrimeField(BigInteger characteristic)
		{
			this.characteristic = characteristic;
		}

		public virtual BigInteger getCharacteristic()
		{
			return characteristic;
		}

		public virtual int getDimension()
		{
			return 1;
		}

		public override bool Equals(object obj)
		{
			if (this == obj)
			{
				return true;
			}
			if (!(obj is PrimeField))
			{
				return false;
			}
			PrimeField other = (PrimeField)obj;
			return characteristic.Equals(other.characteristic);
		}

		public override int GetHashCode()
		{
			return characteristic.GetHashCode();
		}
	}

}