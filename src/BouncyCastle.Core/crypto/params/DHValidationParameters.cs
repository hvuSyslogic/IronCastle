using org.bouncycastle.util;

namespace org.bouncycastle.crypto.@params
{
	
	public class DHValidationParameters
	{
		private byte[] seed;
		private int counter;

		public DHValidationParameters(byte[] seed, int counter)
		{
			this.seed = Arrays.clone(seed);
			this.counter = counter;
		}

		public virtual int getCounter()
		{
			return counter;
		}

		public virtual byte[] getSeed()
		{
			return Arrays.clone(seed);
		}

		public override bool Equals(object o)
		{
			if (!(o is DHValidationParameters))
			{
				return false;
			}

			DHValidationParameters other = (DHValidationParameters)o;

			if (other.counter != this.counter)
			{
				return false;
			}

			return Arrays.areEqual(this.seed, other.seed);
		}

		public override int GetHashCode()
		{
			return counter ^ Arrays.GetHashCode(seed);
		}
	}

}