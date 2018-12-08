using System;
using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.util
{

	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using ECDomainParameters = org.bouncycastle.crypto.@params.ECDomainParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using Ed25519PublicKeyParameters = org.bouncycastle.crypto.@params.Ed25519PublicKeyParameters;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using SecP256R1Curve = org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
	using Strings = org.bouncycastle.util.Strings;


	/// <summary>
	/// OpenSSHPublicKeyUtil utility classes for parsing OpenSSH public keys.
	/// </summary>
	public class OpenSSHPublicKeyUtil
	{
		private OpenSSHPublicKeyUtil()
		{

		}

		private const string RSA = "ssh-rsa";
		private const string ECDSA = "ecdsa";
		private const string ED_25519 = "ssh-ed25519";
		private const string DSS = "ssh-dss";

		/// <summary>
		/// Parse a public key.
		/// <para>
		/// This method accepts the bytes that are Base64 encoded in an OpenSSH public key file.
		/// 
		/// </para>
		/// </summary>
		/// <param name="encoded"> The key. </param>
		/// <returns> An AsymmetricKeyParameter instance. </returns>
		public static AsymmetricKeyParameter parsePublicKey(byte[] encoded)
		{
			SSHBuffer buffer = new SSHBuffer(encoded);
			return parsePublicKey(buffer);
		}

		/// <summary>
		/// Encode a public key from an AsymmetricKeyParameter instance.
		/// </summary>
		/// <param name="cipherParameters"> The key to encode. </param>
		/// <returns> the key OpenSSH encoded. </returns>
		/// <exception cref="IOException"> </exception>
		public static byte[] encodePublicKey(AsymmetricKeyParameter cipherParameters)
		{
			BigInteger e;
			BigInteger n;

			if (cipherParameters == null)
			{
				throw new IllegalArgumentException("cipherParameters was null.");
			}

			if (cipherParameters is RSAKeyParameters)
			{
				if (cipherParameters.isPrivate())
				{
					throw new IllegalArgumentException("RSAKeyParamaters was for encryption");
				}

				e = ((RSAKeyParameters)cipherParameters).getExponent();
				n = ((RSAKeyParameters)cipherParameters).getModulus();

				SSHBuilder builder = new SSHBuilder();
				builder.writeString(RSA);
				builder.rawArray(e.toByteArray());
				builder.rawArray(n.toByteArray());

				return builder.getBytes();

			}
			else if (cipherParameters is ECPublicKeyParameters)
			{
				SSHBuilder builder = new SSHBuilder();

				string name = null;
				if (((ECPublicKeyParameters)cipherParameters).getParameters().getCurve() is SecP256R1Curve)
				{
					name = "nistp256";
				}
				else
				{
					throw new IllegalArgumentException("unable to derive ssh curve name for " + ((ECPublicKeyParameters)cipherParameters).getParameters().getCurve().GetType().getName());
				}

				builder.writeString(ECDSA + "-sha2-" + name); // Magic
				builder.writeString(name);
				builder.rawArray(((ECPublicKeyParameters)cipherParameters).getQ().getEncoded(false)); //Uncompressed
				return builder.getBytes();
			}
			else if (cipherParameters is DSAPublicKeyParameters)
			{
				SSHBuilder builder = new SSHBuilder();
				builder.writeString(DSS);
				builder.rawArray(((DSAPublicKeyParameters)cipherParameters).getParameters().getP().toByteArray());
				builder.rawArray(((DSAPublicKeyParameters)cipherParameters).getParameters().getQ().toByteArray());
				builder.rawArray(((DSAPublicKeyParameters)cipherParameters).getParameters().getG().toByteArray());
				builder.rawArray(((DSAPublicKeyParameters)cipherParameters).getY().toByteArray());
				return builder.getBytes();
			}
			else if (cipherParameters is Ed25519PublicKeyParameters)
			{
				SSHBuilder builder = new SSHBuilder();
				builder.writeString(ED_25519);
				builder.rawArray(((Ed25519PublicKeyParameters)cipherParameters).getEncoded());
				return builder.getBytes();
			}

			throw new IllegalArgumentException("unable to convert " + cipherParameters.GetType().getName() + " to private key");
		}

		/// <summary>
		/// Parse a public key from an SSHBuffer instance.
		/// </summary>
		/// <param name="buffer"> containing the SSH public key. </param>
		/// <returns> A CipherParameters instance. </returns>
		public static AsymmetricKeyParameter parsePublicKey(SSHBuffer buffer)
		{
			AsymmetricKeyParameter result = null;

			string magic = Strings.fromByteArray(buffer.readString());
			if (RSA.Equals(magic))
			{
				BigInteger e = buffer.positiveBigNum();
				BigInteger n = buffer.positiveBigNum();
				result = new RSAKeyParameters(false, n, e);
			}
			else if (DSS.Equals(magic))
			{
				BigInteger p = buffer.positiveBigNum();
				BigInteger q = buffer.positiveBigNum();
				BigInteger g = buffer.positiveBigNum();
				BigInteger pubKey = buffer.positiveBigNum();

				result = new DSAPublicKeyParameters(pubKey, new DSAParameters(p, q, g));
			}
			else if (magic.StartsWith(ECDSA, StringComparison.Ordinal))
			{
				string curveName = Strings.fromByteArray(buffer.readString());
				string nameToFind = curveName;

				if (curveName.StartsWith("nist", StringComparison.Ordinal))
				{
					//
					// NIST names like P-256 are encoded in SSH as nistp256
					//

					nameToFind = curveName.Substring(4);
					nameToFind = nameToFind.Substring(0, 1) + "-" + nameToFind.Substring(1);
				}

				X9ECParameters x9ECParameters = ECNamedCurveTable.getByName(nameToFind);

				if (x9ECParameters == null)
				{
					throw new IllegalStateException("unable to find curve for " + magic + " using curve name " + nameToFind);
				}

				//
				// Extract name of digest from magic string value;
				//
				//String digest = magic.split("-")[1];

				ECCurve curve = x9ECParameters.getCurve();

				byte[] pointRaw = buffer.readString();

				result = new ECPublicKeyParameters(curve.decodePoint(pointRaw), new ECDomainParameters(curve, x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed()));
			}
			else if (magic.StartsWith(ED_25519, StringComparison.Ordinal))
			{
				result = new Ed25519PublicKeyParameters(buffer.readString(), 0);
			}

			if (result == null)
			{
				throw new IllegalArgumentException("unable to parse key");
			}

			if (buffer.hasRemaining())
			{
				throw new IllegalArgumentException("uncoded key has trailing data");
			}

			return result;
		}
	}

}