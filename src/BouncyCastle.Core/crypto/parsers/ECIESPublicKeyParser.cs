using System;
using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.parsers
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using Streams = org.bouncycastle.util.io.Streams;

	public class ECIESPublicKeyParser : KeyParser
	{
		private ECDomainParameters ecParams;

		public ECIESPublicKeyParser(ECDomainParameters ecParams)
		{
			this.ecParams = ecParams;
		}

		public virtual AsymmetricKeyParameter readKey(InputStream stream)
		{
			byte[] V;
			int first = stream.read();

			// Decode the public ephemeral key
			switch (first)
			{
			case 0x00: // infinity
				throw new IOException("Sender's public key invalid.");

			case 0x02: // compressed
			case 0x03: // Byte length calculated as in ECPoint.getEncoded();
				V = new byte[1 + (ecParams.getCurve().getFieldSize() + 7) / 8];
				break;

			case 0x04: // uncompressed or
			case 0x06: // hybrid
			case 0x07: // Byte length calculated as in ECPoint.getEncoded();
				V = new byte[1 + 2 * ((ecParams.getCurve().getFieldSize() + 7) / 8)];
				break;

			default:
				throw new IOException("Sender's public key has invalid point encoding 0x" + Convert.ToString(first, 16));
			}

			V[0] = (byte)first;
			Streams.readFully(stream, V, 1, V.Length - 1);

			return new ECPublicKeyParameters(ecParams.getCurve().decodePoint(V), ecParams);
		}
	}

}