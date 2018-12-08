namespace org.bouncycastle.crypto.@params
{
	public class GOST3410ValidationParameters
	{
		private int x0;
		private int c;
		private long x0L;
		private long cL;


		public GOST3410ValidationParameters(int x0, int c)
		{
			this.x0 = x0;
			this.c = c;
		}

		public GOST3410ValidationParameters(long x0L, long cL)
		{
			this.x0L = x0L;
			this.cL = cL;
		}

		public virtual int getC()
		{
			return c;
		}

		public virtual int getX0()
		{
			return x0;
		}

		public virtual long getCL()
		{
			return cL;
		}

		public virtual long getX0L()
		{
			return x0L;
		}

		public override bool Equals(object o)
		{
			if (!(o is GOST3410ValidationParameters))
			{
				return false;
			}

			GOST3410ValidationParameters other = (GOST3410ValidationParameters)o;

			if (other.c != this.c)
			{
				return false;
			}

			if (other.x0 != this.x0)
			{
				return false;
			}

			if (other.cL != this.cL)
			{
				return false;
			}

			if (other.x0L != this.x0L)
			{
				return false;
			}

			return true;
		}

		public override int GetHashCode()
		{
			return x0 ^ c ^ (int) x0L ^ (int)(x0L >> 32) ^ (int) cL ^ (int)(cL >> 32);
		}
	}

}