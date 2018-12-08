using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{
	public class DTLSEpoch
	{
		private readonly DTLSReplayWindow replayWindow = new DTLSReplayWindow();

		private readonly int epoch;
		private readonly TlsCipher cipher;

		private long sequenceNumber = 0;

		public DTLSEpoch(int epoch, TlsCipher cipher)
		{
			if (epoch < 0)
			{
				throw new IllegalArgumentException("'epoch' must be >= 0");
			}
			if (cipher == null)
			{
				throw new IllegalArgumentException("'cipher' cannot be null");
			}

			this.epoch = epoch;
			this.cipher = cipher;
		}

		public virtual long allocateSequenceNumber()
		{
			// TODO Check for overflow
			return sequenceNumber++;
		}

		public virtual TlsCipher getCipher()
		{
			return cipher;
		}

		public virtual int getEpoch()
		{
			return epoch;
		}

		public virtual DTLSReplayWindow getReplayWindow()
		{
			return replayWindow;
		}

		public virtual long getSequenceNumber()
		{
			return sequenceNumber;
		}
	}

}