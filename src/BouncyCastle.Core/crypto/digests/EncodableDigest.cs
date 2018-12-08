﻿namespace org.bouncycastle.crypto.digests
{
	/// <summary>
	///  Encodable digests allow you to download an encoded copy of their internal state. This is useful for the situation where
	///  you need to generate a signature on an external device and it allows for "sign with last round", so a copy of the
	///  internal state of the digest, plus the last few blocks of the message are all that needs to be sent, rather than the
	///  entire message.
	/// </summary>
	public interface EncodableDigest
	{
		/// <summary>
		/// Return an encoded byte array for the digest's internal state
		/// </summary>
		/// <returns> an encoding of the digests internal state. </returns>
		byte[] getEncodedState();
	}

}