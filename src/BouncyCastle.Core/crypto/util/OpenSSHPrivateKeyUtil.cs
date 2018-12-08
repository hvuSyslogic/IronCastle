using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.util
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using RSAPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey;
	using ECPrivateKey = org.bouncycastle.asn1.sec.ECPrivateKey;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DSAParameters = org.bouncycastle.crypto.@params.DSAParameters;
	using DSAPrivateKeyParameters = org.bouncycastle.crypto.@params.DSAPrivateKeyParameters;
	using ECNamedDomainParameters = org.bouncycastle.crypto.@params.ECNamedDomainParameters;
	using ECPrivateKeyParameters = org.bouncycastle.crypto.@params.ECPrivateKeyParameters;
	using Ed25519PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed25519PrivateKeyParameters;
	using Ed25519PublicKeyParameters = org.bouncycastle.crypto.@params.Ed25519PublicKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;


	/// <summary>
	/// A collection of utility methods for parsing OpenSSH private keys.
	/// </summary>
	public class OpenSSHPrivateKeyUtil
	{
		private OpenSSHPrivateKeyUtil()
		{

		}

		/// <summary>
		/// Magic value for propriety OpenSSH private key.
		/// 
		/// </summary>
		internal static readonly byte[] AUTH_MAGIC = Strings.toByteArray("openssh-key-v1\0"); // C string so null terminated

		/// <summary>
		/// Encode a cipher parameters into an OpenSSH private key.
		/// This does not add headers like ----BEGIN RSA PRIVATE KEY----
		/// </summary>
		/// <param name="params"> the cipher parameters. </param>
		/// <returns> a byte array </returns>
		public static byte[] encodePrivateKey(AsymmetricKeyParameter @params)
		{
			if (@params == null)
			{
				throw new IllegalArgumentException("param is null");
			}

			if (@params is RSAPrivateCrtKeyParameters)
			{
				PrivateKeyInfo pInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(@params);

				return pInfo.parsePrivateKey().toASN1Primitive().getEncoded();
			}
			else if (@params is ECPrivateKeyParameters)
			{
				PrivateKeyInfo pInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(@params);

				return pInfo.parsePrivateKey().toASN1Primitive().getEncoded();
			}
			else if (@params is DSAPrivateKeyParameters)
			{
				ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(new ASN1Integer(0));
				vec.add(new ASN1Integer(((DSAPrivateKeyParameters)@params).getParameters().getP()));
				vec.add(new ASN1Integer(((DSAPrivateKeyParameters)@params).getParameters().getQ()));
				vec.add(new ASN1Integer(((DSAPrivateKeyParameters)@params).getParameters().getG()));

				// public key = g.modPow(x, p);

				BigInteger pubKey = ((DSAPrivateKeyParameters)@params).getParameters().getG().modPow(((DSAPrivateKeyParameters)@params).getX(), ((DSAPrivateKeyParameters)@params).getParameters().getP());
				vec.add(new ASN1Integer(pubKey));

				vec.add(new ASN1Integer(((DSAPrivateKeyParameters)@params).getX()));
				try
				{
					return (new DERSequence(vec)).getEncoded();
				}
				catch (Exception ex)
				{
					throw new IllegalStateException("unable to encode DSAPrivateKeyParameters " + ex.Message, ex);
				}
			}
			else if (@params is Ed25519PrivateKeyParameters)
			{
				SSHBuilder builder = new SSHBuilder();

				builder.write(AUTH_MAGIC);
				builder.writeString("none");
				builder.writeString("none");
				builder.u32(0); // Zero length of the KDF

				builder.u32(1);

				Ed25519PublicKeyParameters publicKeyParameters = ((Ed25519PrivateKeyParameters)@params).generatePublicKey();

				byte[] pkEncoded = OpenSSHPublicKeyUtil.encodePublicKey(publicKeyParameters);
				builder.rawArray(pkEncoded);

				SSHBuilder pkBuild = new SSHBuilder();

				pkBuild.u32(0x00ff00ff);
				pkBuild.u32(0x00ff00ff);

				pkBuild.writeString("ssh-ed25519");

				byte[] pubKeyEncoded = ((Ed25519PrivateKeyParameters)@params).generatePublicKey().getEncoded();

				pkBuild.rawArray(pubKeyEncoded); // Public key written as length defined item.

				// The private key in SSH is 64 bytes long and is the concatenation of the private and the public keys
				pkBuild.rawArray(Arrays.concatenate(((Ed25519PrivateKeyParameters)@params).getEncoded(), pubKeyEncoded));
				pkBuild.u32(0); // No comment.
				builder.rawArray(pkBuild.getBytes());

				return builder.getBytes();
			}

			throw new IllegalArgumentException("unable to convert " + @params.GetType().getName() + " to openssh private key");

		}

		/// <summary>
		/// Parse a private key.
		/// <para>
		/// This method accepts the body of the OpenSSH private key.
		/// The easiest way to extract the body is to use PemReader, for example:
		/// </para>
		/// <para>
		/// byte[] blob = new PemReader([reader]).readPemObject().getContent();
		/// CipherParameters params = parsePrivateKeyBlob(blob);
		/// 
		/// </para>
		/// </summary>
		/// <param name="blob"> The key. </param>
		/// <returns> A cipher parameters instance. </returns>
		public static AsymmetricKeyParameter parsePrivateKeyBlob(byte[] blob)
		{
			AsymmetricKeyParameter result = null;

			if (blob[0] == 0x30)
			{
				ASN1Sequence sequence = ASN1Sequence.getInstance(blob);

				if (sequence.size() == 6)
				{
					if (allIntegers(sequence) && ((ASN1Integer)sequence.getObjectAt(0)).getPositiveValue().Equals(BigInteger.ZERO))
					{
						// length of 6 and all Integers -- DSA
						result = new DSAPrivateKeyParameters(((ASN1Integer)sequence.getObjectAt(5)).getPositiveValue(), new DSAParameters(((ASN1Integer)sequence.getObjectAt(1)).getPositiveValue(), ((ASN1Integer)sequence.getObjectAt(2)).getPositiveValue(), ((ASN1Integer)sequence.getObjectAt(3)).getPositiveValue())
					   );
					}
				}
				else if (sequence.size() == 9)
				{
					if (allIntegers(sequence) && ((ASN1Integer)sequence.getObjectAt(0)).getPositiveValue().Equals(BigInteger.ZERO))
					{
						// length of 8 and all Integers -- RSA
						RSAPrivateKey rsaPrivateKey = RSAPrivateKey.getInstance(sequence);

						result = new RSAPrivateCrtKeyParameters(rsaPrivateKey.getModulus(), rsaPrivateKey.getPublicExponent(), rsaPrivateKey.getPrivateExponent(), rsaPrivateKey.getPrime1(), rsaPrivateKey.getPrime2(), rsaPrivateKey.getExponent1(), rsaPrivateKey.getExponent2(), rsaPrivateKey.getCoefficient());
					}
				}
				else if (sequence.size() == 4)
				{
					if (sequence.getObjectAt(3) is DERTaggedObject && sequence.getObjectAt(2) is DERTaggedObject)
					{
						ECPrivateKey ecPrivateKey = ECPrivateKey.getInstance(sequence);
						ASN1ObjectIdentifier curveOID = (ASN1ObjectIdentifier)ecPrivateKey.getParameters();
						X9ECParameters x9Params = ECNamedCurveTable.getByOID(curveOID);
						result = new ECPrivateKeyParameters(ecPrivateKey.getKey(), new ECNamedDomainParameters(curveOID, x9Params.getCurve(), x9Params.getG(), x9Params.getN(), x9Params.getH(), x9Params.getSeed()));
					}
				}
			}
			else
			{
				SSHBuffer kIn = new SSHBuffer(AUTH_MAGIC, blob);
				// Cipher name.
				string cipherName = Strings.fromByteArray(kIn.readString());

				if (!"none".Equals(cipherName))
				{
					throw new IllegalStateException("encrypted keys not supported");
				}

				// KDF name
				kIn.readString();

				// KDF options
				kIn.readString();

				long publicKeyCount = kIn.readU32();

				for (int l = 0; l != publicKeyCount; l++)
				{
					// Burn off public keys.
					OpenSSHPublicKeyUtil.parsePublicKey(kIn.readString());
				}

				SSHBuffer pkIn = new SSHBuffer(kIn.readPaddedString());
				int check1 = pkIn.readU32();
				int check2 = pkIn.readU32();

				if (check1 != check2)
				{
					throw new IllegalStateException("private key check values are not the same");
				}

				string keyType = Strings.fromByteArray(pkIn.readString());

				if ("ssh-ed25519".Equals(keyType))
				{
					//
					// Skip public key
					//
					pkIn.readString();
					byte[] edPrivateKey = pkIn.readString();

					result = new Ed25519PrivateKeyParameters(edPrivateKey, 0);
				}
				else
				{
					throw new IllegalStateException("can not parse private key of type " + keyType);
				}
			}

			if (result == null)
			{
				throw new IllegalArgumentException("unable to parse key");
			}

			return result;
		}

		/// <summary>
		/// allIntegers returns true if the sequence holds only ASN1Integer types.
		/// 
		/// </summary>
		private static bool allIntegers(ASN1Sequence sequence)
		{
			for (int t = 0; t < sequence.size(); t++)
			{
				if (!(sequence.getObjectAt(t) is ASN1Integer))
				{
					return false;

				}
			}
			return true;
		}
	}

}