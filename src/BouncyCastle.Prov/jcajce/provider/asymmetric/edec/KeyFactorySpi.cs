using org.bouncycastle.asn1.edec;

namespace org.bouncycastle.jcajce.provider.asymmetric.edec
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using EdECObjectIdentifiers = org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Ed25519PrivateKeyParameters = org.bouncycastle.crypto.@params.Ed25519PrivateKeyParameters;
	using Ed25519PublicKeyParameters = org.bouncycastle.crypto.@params.Ed25519PublicKeyParameters;
	using OpenSSHPrivateKeyUtil = org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
	using OpenSSHPublicKeyUtil = org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
	using BaseKeyFactorySpi = org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
	using AsymmetricKeyInfoConverter = org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
	using OpenSSHPrivateKeySpec = org.bouncycastle.jce.spec.OpenSSHPrivateKeySpec;
	using OpenSSHPublicKeySpec = org.bouncycastle.jce.spec.OpenSSHPublicKeySpec;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class KeyFactorySpi : BaseKeyFactorySpi, AsymmetricKeyInfoConverter
	{
		internal static readonly byte[] x448Prefix = Hex.decode("3042300506032b656f033900");
		internal static readonly byte[] x25519Prefix = Hex.decode("302a300506032b656e032100");
		internal static readonly byte[] Ed448Prefix = Hex.decode("3043300506032b6571033a00");
		internal static readonly byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");

		private const byte x448_type = 0x6f;
		private const byte x25519_type = 0x6e;
		private const byte Ed448_type = 0x71;
		private const byte Ed25519_type = 0x70;

		internal string algorithm;
		private readonly bool isXdh;
		private readonly int specificBase;

		public KeyFactorySpi(string algorithm, bool isXdh, int specificBase)
		{
			this.algorithm = algorithm;
			this.isXdh = isXdh;
			this.specificBase = specificBase;
		}

		public virtual Key engineTranslateKey(Key key)
		{
			throw new InvalidKeyException("key type unknown");
		}

		public override KeySpec engineGetKeySpec(Key key, Class spec)
		{
			if (spec.isAssignableFrom(typeof(OpenSSHPrivateKeySpec)) && key is BCEdDSAPrivateKey)
			{
				try
				{
					//
					// The DEROctetString at element 2 is an encoded DEROctetString with the private key value
					// within it.
					//

					ASN1Sequence seq = ASN1Sequence.getInstance(key.getEncoded());
					DEROctetString val = (DEROctetString)seq.getObjectAt(2);
					ASN1InputStream @in = new ASN1InputStream(val.getOctets());

					return new OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(new Ed25519PrivateKeyParameters(((DEROctetString)@in.readObject()).getOctets(), 0)));
				}
				catch (IOException ex)
				{
					throw new InvalidKeySpecException(ex.Message, ex.InnerException);
				}

			}
			else if (spec.isAssignableFrom(typeof(OpenSSHPublicKeySpec)) && key is BCEdDSAPublicKey)
			{
				try
				{
					return new OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(new Ed25519PublicKeyParameters(key.getEncoded(), Ed25519Prefix.Length)));
				}
				catch (IOException ex)
				{
					throw new InvalidKeySpecException(ex.Message, ex.InnerException);
				}
			}

			return base.engineGetKeySpec(key, spec);
		}

		public override PrivateKey engineGeneratePrivate(KeySpec keySpec)
		{
			if (keySpec is OpenSSHPrivateKeySpec)
			{
				CipherParameters parameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(((OpenSSHPrivateKeySpec)keySpec).getEncoded());
				if (parameters is Ed25519PrivateKeyParameters)
				{
					return new BCEdDSAPrivateKey((Ed25519PrivateKeyParameters)parameters);
				}
				throw new IllegalStateException("openssh private key not Ed25519 private key");
			}

			return base.engineGeneratePrivate(keySpec);
		}

		public override PublicKey engineGeneratePublic(KeySpec keySpec)
		{
			if (keySpec is X509EncodedKeySpec)
			{
				byte[] enc = ((X509EncodedKeySpec)keySpec).getEncoded();
				// optimise if we can
				if (specificBase == 0 || specificBase == enc[8])
				{
					switch (enc[8])
					{
					case x448_type:
						return new BCXDHPublicKey(x448Prefix, enc);
					case x25519_type:
						return new BCXDHPublicKey(x25519Prefix, enc);
					case Ed448_type:
						return new BCEdDSAPublicKey(Ed448Prefix, enc);
					case Ed25519_type:
						return new BCEdDSAPublicKey(Ed25519Prefix, enc);
					default:
						return base.engineGeneratePublic(keySpec);
					}
				}
			}
			else if (keySpec is OpenSSHPublicKeySpec)
			{
				CipherParameters parameters = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)keySpec).getEncoded());
				if (parameters is Ed25519PublicKeyParameters)
				{
					return new BCEdDSAPublicKey(new byte[0], ((Ed25519PublicKeyParameters)parameters).getEncoded());
				}

				throw new IllegalStateException("openssh public key not Ed25519 public key");
			}

			return base.engineGeneratePublic(keySpec);
		}

		public override PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

			if (isXdh)
			{
				if ((specificBase == 0 || specificBase == x448_type) && algOid.Equals(EdECObjectIdentifiers_Fields.id_X448))
				{
					return new BCXDHPrivateKey(keyInfo);
				}
				if ((specificBase == 0 || specificBase == x25519_type) && algOid.Equals(EdECObjectIdentifiers_Fields.id_X25519))
				{
					return new BCXDHPrivateKey(keyInfo);
				}
			}
			else if (algOid.Equals(EdECObjectIdentifiers_Fields.id_Ed448) || algOid.Equals(EdECObjectIdentifiers_Fields.id_Ed25519))
			{
				if ((specificBase == 0 || specificBase == Ed448_type) && algOid.Equals(EdECObjectIdentifiers_Fields.id_Ed448))
				{
					return new BCEdDSAPrivateKey(keyInfo);
				}
				if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.Equals(EdECObjectIdentifiers_Fields.id_Ed25519))
				{
					return new BCEdDSAPrivateKey(keyInfo);
				}
			}

			throw new IOException("algorithm identifier " + algOid + " in key not recognized");
		}

		public override PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
		{
			ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

			if (isXdh)
			{
				if ((specificBase == 0 || specificBase == x448_type) && algOid.Equals(EdECObjectIdentifiers_Fields.id_X448))
				{
					return new BCXDHPublicKey(keyInfo);
				}
				if ((specificBase == 0 || specificBase == x25519_type) && algOid.Equals(EdECObjectIdentifiers_Fields.id_X25519))
				{
					return new BCXDHPublicKey(keyInfo);
				}
			}
			else if (algOid.Equals(EdECObjectIdentifiers_Fields.id_Ed448) || algOid.Equals(EdECObjectIdentifiers_Fields.id_Ed25519))
			{
				if ((specificBase == 0 || specificBase == Ed448_type) && algOid.Equals(EdECObjectIdentifiers_Fields.id_Ed448))
				{
					return new BCEdDSAPublicKey(keyInfo);
				}
				if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.Equals(EdECObjectIdentifiers_Fields.id_Ed25519))
				{
					return new BCEdDSAPublicKey(keyInfo);
				}
			}

			throw new IOException("algorithm identifier " + algOid + " in key not recognized");
		}

		public class XDH : KeyFactorySpi
		{
			public XDH() : base("XDH", true, 0)
			{
			}
		}

		public class X448 : KeyFactorySpi
		{
			public X448() : base("X448", true, x448_type)
			{
			}
		}

		public class X25519 : KeyFactorySpi
		{
			public X25519() : base("X25519", true, x25519_type)
			{
			}
		}

		public class EDDSA : KeyFactorySpi
		{
			public EDDSA() : base("EdDSA", false, 0)
			{
			}
		}

		public class ED448 : KeyFactorySpi
		{
			public ED448() : base("Ed448", false, Ed448_type)
			{
			}
		}

		public class ED25519 : KeyFactorySpi
		{
			public ED25519() : base("Ed25519", false, Ed25519_type)
			{
			}
		}
	}
}