namespace org.bouncycastle.crypto.@params
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class DSAValidationParameters
	{
		private int usageIndex;
		private byte[] seed;
		private int counter;

		public DSAValidationParameters(byte[] seed, int counter) : this(seed, counter, -1)
		{
		}

		public DSAValidationParameters(byte[] seed, int counter, int usageIndex)
		{
			this.seed = Arrays.clone(seed);
			this.counter = counter;
			this.usageIndex = usageIndex;
		}

		public virtual int getCounter()
		{
			return counter;
		}

		public virtual byte[] getSeed()
		{
			return Arrays.clone(seed);
		}

		public virtual int getUsageIndex()
		{
			return usageIndex;
		}

		public override int GetHashCode()
		{
			return counter ^ Arrays.GetHashCode(seed);
		}

		public override bool Equals(object o)
		{
			if (!(o is DSAValidationParameters))
			{
				return false;
			}

			DSAValidationParameters other = (DSAValidationParameters)o;

			if (other.counter != this.counter)
			{
				return false;
			}

			return Arrays.areEqual(this.seed, other.seed);
		}
	}

}