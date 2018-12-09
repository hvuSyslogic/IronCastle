﻿namespace org.bouncycastle.crypto.tls
{
	public interface TlsSession
	{
		SessionParameters exportSessionParameters();

		byte[] getSessionID();

		void invalidate();

		bool isResumable();
	}

}