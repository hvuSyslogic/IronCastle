using org.bouncycastle.asn1.eac;
using org.bouncycastle.eac.@operator.jcajce;

namespace org.bouncycastle.eac.@operator.jcajce
{

	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using OperatorStreamException = org.bouncycastle.@operator.OperatorStreamException;
	using RuntimeOperatorException = org.bouncycastle.@operator.RuntimeOperatorException;

	public class JcaEACSignerBuilder
	{
		private static readonly Hashtable sigNames = new Hashtable();

		static JcaEACSignerBuilder()
		{
			sigNames.put("SHA1withRSA", EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_1);
			sigNames.put("SHA256withRSA", EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_256);
			sigNames.put("SHA1withRSAandMGF1", EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_1);
			sigNames.put("SHA256withRSAandMGF1", EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_256);
			sigNames.put("SHA512withRSA", EACObjectIdentifiers_Fields.id_TA_RSA_v1_5_SHA_512);
			sigNames.put("SHA512withRSAandMGF1", EACObjectIdentifiers_Fields.id_TA_RSA_PSS_SHA_512);

			sigNames.put("SHA1withECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_1);
			sigNames.put("SHA224withECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_224);
			sigNames.put("SHA256withECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_256);
			sigNames.put("SHA384withECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_384);
			sigNames.put("SHA512withECDSA", EACObjectIdentifiers_Fields.id_TA_ECDSA_SHA_512);
		}

		private EACHelper helper = new DefaultEACHelper();

		public virtual JcaEACSignerBuilder setProvider(string providerName)
		{
			this.helper = new NamedEACHelper(providerName);

			return this;
		}

		public virtual JcaEACSignerBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderEACHelper(provider);

			return this;
		}

		public virtual EACSigner build(string algorithm, PrivateKey privKey)
		{
			return build((ASN1ObjectIdentifier)sigNames.get(algorithm), privKey);
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.eac.operator.EACSigner build(final org.bouncycastle.asn1.ASN1ObjectIdentifier usageOid, java.security.PrivateKey privKey) throws org.bouncycastle.operator.OperatorCreationException
		public virtual EACSigner build(ASN1ObjectIdentifier usageOid, PrivateKey privKey)
		{
			Signature sig;
			try
			{
				sig = helper.getSignature(usageOid);

				sig.initSign(privKey);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new OperatorCreationException("unable to find algorithm: " + e.Message, e);
			}
			catch (NoSuchProviderException e)
			{
				throw new OperatorCreationException("unable to find provider: " + e.Message, e);
			}
			catch (InvalidKeyException e)
			{
				throw new OperatorCreationException("invalid key: " + e.Message, e);
			}

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final SignatureOutputStream sigStream = new SignatureOutputStream(sig);
			SignatureOutputStream sigStream = new SignatureOutputStream(this, sig);

			return new EACSignerAnonymousInnerClass(this, usageOid, e, sigStream);
		}

		public class EACSignerAnonymousInnerClass : EACSigner
		{
			private readonly JcaEACSignerBuilder outerInstance;

			private ASN1ObjectIdentifier usageOid;
			private NoSuchAlgorithmException e;
			private JcaEACSignerBuilder.SignatureOutputStream sigStream;

			public EACSignerAnonymousInnerClass(JcaEACSignerBuilder outerInstance, ASN1ObjectIdentifier usageOid, NoSuchAlgorithmException e, JcaEACSignerBuilder.SignatureOutputStream sigStream)
			{
				this.outerInstance = outerInstance;
				this.usageOid = usageOid;
				this.e = e;
				this.sigStream = sigStream;
			}

			public ASN1ObjectIdentifier getUsageIdentifier()
			{
				return usageOid;
			}

			public OutputStream getOutputStream()
			{
				return sigStream;
			}

			public byte[] getSignature()
			{
				try
				{
					byte[] signature = sigStream.getSignature();

					if (usageOid.on(EACObjectIdentifiers_Fields.id_TA_ECDSA))
					{
						return reencode(signature);
					}

					return signature;
				}
				catch (SignatureException e)
				{
					throw new RuntimeOperatorException("exception obtaining signature: " + e.Message, e);
				}
			}
		}

		public static int max(int el1, int el2)
		{
			return el1 > el2 ? el1 : el2;
		}

		private static byte[] reencode(byte[] rawSign)
		{
			ASN1Sequence sData = ASN1Sequence.getInstance(rawSign);

			BigInteger r = ASN1Integer.getInstance(sData.getObjectAt(0)).getValue();
			BigInteger s = ASN1Integer.getInstance(sData.getObjectAt(1)).getValue();

			byte[] rB = r.toByteArray();
			byte[] sB = s.toByteArray();

			int rLen = unsignedIntLength(rB);
			int sLen = unsignedIntLength(sB);

			byte[] ret;
			int len = max(rLen, sLen);

			ret = new byte[len * 2];
			Arrays.fill(ret, (byte)0);

			copyUnsignedInt(rB, ret, len - rLen);
			copyUnsignedInt(sB, ret, 2 * len - sLen);

			return ret;
		}

		private static int unsignedIntLength(byte[] i)
		{
			int len = i.Length;
			if (i[0] == 0)
			{
				len--;
			}

			return len;
		}

		private static void copyUnsignedInt(byte[] src, byte[] dst, int offset)
		{
			int len = src.Length;
			int readoffset = 0;
			if (src[0] == 0)
			{
				len--;
				readoffset = 1;
			}

			JavaSystem.arraycopy(src, readoffset, dst, offset, len);
		}

		public class SignatureOutputStream : OutputStream
		{
			private readonly JcaEACSignerBuilder outerInstance;

			internal Signature sig;

			public SignatureOutputStream(JcaEACSignerBuilder outerInstance, Signature sig)
			{
				this.outerInstance = outerInstance;
				this.sig = sig;
			}

			public virtual void write(byte[] bytes, int off, int len)
			{
				try
				{
					sig.update(bytes, off, len);
				}
				catch (SignatureException e)
				{
					throw new OperatorStreamException("exception in content signer: " + e.Message, e);
				}
			}

			public virtual void write(byte[] bytes)
			{
				try
				{
					sig.update(bytes);
				}
				catch (SignatureException e)
				{
					throw new OperatorStreamException("exception in content signer: " + e.Message, e);
				}
			}

			public virtual void write(int b)
			{
				try
				{
					sig.update((byte)b);
				}
				catch (SignatureException e)
				{
					throw new OperatorStreamException("exception in content signer: " + e.Message, e);
				}
			}

			public virtual byte[] getSignature()
			{
				return sig.sign();
			}
		}
	}

}