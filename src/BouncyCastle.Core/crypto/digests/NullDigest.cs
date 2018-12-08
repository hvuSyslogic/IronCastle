using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.digests
{

	using Arrays = org.bouncycastle.util.Arrays;


	public class NullDigest : Digest
	{
		private OpenByteArrayOutputStream bOut = new OpenByteArrayOutputStream();

		public virtual string getAlgorithmName()
		{
			return "NULL";
		}

		public virtual int getDigestSize()
		{
			return bOut.size();
		}

		public virtual void update(byte @in)
		{
			bOut.write(@in);
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			bOut.write(@in, inOff, len);
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			int size = bOut.size();

			bOut.copy(@out, outOff);

			reset();

			return size;
		}

		public virtual void reset()
		{
			bOut.reset();
		}

		public class OpenByteArrayOutputStream : ByteArrayOutputStream
		{
			public virtual void reset()
			{
				base.reset();

				Arrays.clear(buf);
			}

			public virtual void copy(byte[] @out, int outOff)
			{
				JavaSystem.arraycopy(buf, 0, @out, outOff, this.size());
			}
		}
	}
}