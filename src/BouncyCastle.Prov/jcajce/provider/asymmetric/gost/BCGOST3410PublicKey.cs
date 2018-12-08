using org.bouncycastle.asn1.cryptopro;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.gost
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using GOST3410PublicKeyAlgParameters = org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using GOST3410PublicKeyParameters = org.bouncycastle.crypto.@params.GOST3410PublicKeyParameters;
	using GOST3410Util = org.bouncycastle.jcajce.provider.asymmetric.util.GOST3410Util;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using GOST3410Params = org.bouncycastle.jce.interfaces.GOST3410Params;
	using GOST3410PublicKey = org.bouncycastle.jce.interfaces.GOST3410PublicKey;
	using GOST3410ParameterSpec = org.bouncycastle.jce.spec.GOST3410ParameterSpec;
	using GOST3410PublicKeyParameterSetSpec = org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;
	using GOST3410PublicKeySpec = org.bouncycastle.jce.spec.GOST3410PublicKeySpec;

	public class BCGOST3410PublicKey : GOST3410PublicKey
	{
		internal const long serialVersionUID = -6251023343619275990L;

		private BigInteger y;
		[NonSerialized]
		private GOST3410Params gost3410Spec;

		public BCGOST3410PublicKey(GOST3410PublicKeySpec spec)
		{
			this.y = spec.getY();
			this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec(spec.getP(), spec.getQ(), spec.getA()));
		}

		public BCGOST3410PublicKey(GOST3410PublicKey key)
		{
			this.y = key.getY();
			this.gost3410Spec = key.getParameters();
		}

		public BCGOST3410PublicKey(GOST3410PublicKeyParameters @params, GOST3410ParameterSpec spec)
		{
			this.y = @params.getY();
			this.gost3410Spec = spec;
		}

		public BCGOST3410PublicKey(BigInteger y, GOST3410ParameterSpec gost3410Spec)
		{
			this.y = y;
			this.gost3410Spec = gost3410Spec;
		}

		public BCGOST3410PublicKey(SubjectPublicKeyInfo info)
		{
			GOST3410PublicKeyAlgParameters @params = GOST3410PublicKeyAlgParameters.getInstance(info.getAlgorithm().getParameters());
			DEROctetString derY;

			try
			{
				derY = (DEROctetString)info.parsePublicKey();

				byte[] keyEnc = derY.getOctets();
				byte[] keyBytes = new byte[keyEnc.Length];

				for (int i = 0; i != keyEnc.Length; i++)
				{
					keyBytes[i] = keyEnc[keyEnc.Length - 1 - i]; // was little endian
				}

				this.y = new BigInteger(1, keyBytes);
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("invalid info structure in GOST3410 public key");
			}

			this.gost3410Spec = GOST3410ParameterSpec.fromPublicKeyAlg(@params);
		}

		public virtual string getAlgorithm()
		{
			return "GOST3410";
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getEncoded()
		{
			SubjectPublicKeyInfo info;
			byte[] keyEnc = this.getY().toByteArray();
			byte[] keyBytes;

			if (keyEnc[0] == 0)
			{
				keyBytes = new byte[keyEnc.Length - 1];
			}
			else
			{
				keyBytes = new byte[keyEnc.Length];
			}

			for (int i = 0; i != keyBytes.Length; i++)
			{
				keyBytes[i] = keyEnc[keyEnc.Length - 1 - i]; // must be little endian
			}

			try
			{
				if (gost3410Spec is GOST3410ParameterSpec)
				{
					if (!string.ReferenceEquals(gost3410Spec.getEncryptionParamSetOID(), null))
					{
						info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3410_94, new GOST3410PublicKeyAlgParameters(new ASN1ObjectIdentifier(gost3410Spec.getPublicKeyParamSetOID()), new ASN1ObjectIdentifier(gost3410Spec.getDigestParamSetOID()), new ASN1ObjectIdentifier(gost3410Spec.getEncryptionParamSetOID()))), new DEROctetString(keyBytes));
					}
					else
					{
						info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3410_94, new GOST3410PublicKeyAlgParameters(new ASN1ObjectIdentifier(gost3410Spec.getPublicKeyParamSetOID()), new ASN1ObjectIdentifier(gost3410Spec.getDigestParamSetOID()))), new DEROctetString(keyBytes));
					}
				}
				else
				{
					info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers_Fields.gostR3410_94), new DEROctetString(keyBytes));
				}

				return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual GOST3410Params getParameters()
		{
			return gost3410Spec;
		}

		public virtual BigInteger getY()
		{
			return y;
		}

		public override string ToString()
		{
			try
			{
				return GOSTUtil.publicKeyToString("GOST3410", y, ((GOST3410PublicKeyParameters)GOST3410Util.generatePublicKeyParameter(this)).getParameters());
			}
			catch (InvalidKeyException e)
			{
				throw new IllegalStateException(e.Message); // should not be possible
			}
		}

		public override bool Equals(object o)
		{
			if (o is BCGOST3410PublicKey)
			{
				BCGOST3410PublicKey other = (BCGOST3410PublicKey)o;

				return this.y.Equals(other.y) && this.gost3410Spec.Equals(other.gost3410Spec);
			}

			return false;
		}

		public override int GetHashCode()
		{
			return y.GetHashCode() ^ gost3410Spec.GetHashCode();
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			string publicKeyParamSetOID = (string)@in.readObject();
			if (!string.ReferenceEquals(publicKeyParamSetOID, null))
			{
				this.gost3410Spec = new GOST3410ParameterSpec(publicKeyParamSetOID, (string)@in.readObject(), (string)@in.readObject());
			}
			else
			{
				this.gost3410Spec = new GOST3410ParameterSpec(new GOST3410PublicKeyParameterSetSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject(), (BigInteger)@in.readObject()));
				@in.readObject();
				@in.readObject();
			}
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			if (!string.ReferenceEquals(gost3410Spec.getPublicKeyParamSetOID(), null))
			{
				@out.writeObject(gost3410Spec.getPublicKeyParamSetOID());
				@out.writeObject(gost3410Spec.getDigestParamSetOID());
				@out.writeObject(gost3410Spec.getEncryptionParamSetOID());
			}
			else
			{
				@out.writeObject(null);
				@out.writeObject(gost3410Spec.getPublicKeyParameters().getP());
				@out.writeObject(gost3410Spec.getPublicKeyParameters().getQ());
				@out.writeObject(gost3410Spec.getPublicKeyParameters().getA());
				@out.writeObject(gost3410Spec.getDigestParamSetOID());
				@out.writeObject(gost3410Spec.getEncryptionParamSetOID());
			}
		}
	}

}