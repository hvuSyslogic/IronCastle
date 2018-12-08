using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class TlsSessionImpl : TlsSession
	{
		internal readonly byte[] sessionID;
		internal readonly SessionParameters sessionParameters;
		internal bool resumable;

		public TlsSessionImpl(byte[] sessionID, SessionParameters sessionParameters)
		{
			if (sessionID == null)
			{
				throw new IllegalArgumentException("'sessionID' cannot be null");
			}
			if (sessionID.Length > 32)
			{
				throw new IllegalArgumentException("'sessionID' cannot be longer than 32 bytes");
			}

			this.sessionID = Arrays.clone(sessionID);
			this.sessionParameters = sessionParameters;
			this.resumable = sessionID.Length > 0 && null != sessionParameters && sessionParameters.isExtendedMasterSecret();
		}

		public virtual SessionParameters exportSessionParameters()
		{
			lock (this)
			{
				return this.sessionParameters == null ? null : this.sessionParameters.copy();
			}
		}

		public virtual byte[] getSessionID()
		{
			lock (this)
			{
				return sessionID;
			}
		}

		public virtual void invalidate()
		{
			lock (this)
			{
				this.resumable = false;
			}
		}

		public virtual bool isResumable()
		{
			lock (this)
			{
				return resumable;
			}
		}
	}

}