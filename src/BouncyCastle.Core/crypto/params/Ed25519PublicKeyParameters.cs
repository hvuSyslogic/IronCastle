﻿using org.bouncycastle.math.ec.rfc8032;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.util;
using org.bouncycastle.util.io;

namespace org.bouncycastle.crypto.@params
{

			
	public sealed class Ed25519PublicKeyParameters : AsymmetricKeyParameter
	{
		public const int KEY_SIZE = Ed25519.PUBLIC_KEY_SIZE;

		private readonly byte[] data = new byte[KEY_SIZE];

		public Ed25519PublicKeyParameters(byte[] buf, int off) : base(false)
		{

			JavaSystem.arraycopy(buf, off, data, 0, KEY_SIZE);
		}

		public Ed25519PublicKeyParameters(InputStream input) : base(false)
		{

			if (KEY_SIZE != Streams.readFully(input, data))
			{
				throw new EOFException("EOF encountered in middle of Ed25519 public key");
			}
		}

		public void encode(byte[] buf, int off)
		{
			JavaSystem.arraycopy(data, 0, buf, off, KEY_SIZE);
		}

		public byte[] getEncoded()
		{
			return Arrays.clone(data);
		}
	}

}