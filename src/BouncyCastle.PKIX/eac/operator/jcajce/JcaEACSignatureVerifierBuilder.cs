using org.bouncycastle.eac.@operator.jcajce;
using org.bouncycastle.asn1.eac;

using System;

namespace org.bouncycastle.eac.@operator.jcajce
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using EACObjectIdentifiers = org.bouncycastle.asn1.eac.EACObjectIdentifiers;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using OperatorStreamException = org.bouncycastle.@operator.OperatorStreamException;
	using RuntimeOperatorException = org.bouncycastle.@operator.RuntimeOperatorException;

	public class JcaEACSignatureVerifierBuilder
	{
		private EACHelper helper = new DefaultEACHelper();

		public virtual JcaEACSignatureVerifierBuilder setProvider(string providerName)
		{
			this.helper = new NamedEACHelper(providerName);

			return this;
		}

		public virtual JcaEACSignatureVerifierBuilder setProvider(Provider provider)
		{
			this.helper = new ProviderEACHelper(provider);

			return this;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.eac.operator.EACSignatureVerifier build(final org.bouncycastle.asn1.ASN1ObjectIdentifier usageOid, java.security.PublicKey pubKey) throws org.bouncycastle.operator.OperatorCreationException
		public virtual EACSignatureVerifier build(ASN1ObjectIdentifier usageOid, PublicKey pubKey)
		{
			Signature sig;
			try
			{
				sig = helper.getSignature(usageOid);

				sig.initVerify(pubKey);
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

			return new EACSignatureVerifierAnonymousInnerClass(this, usageOid, e, sigStream);
		}

		public class EACSignatureVerifierAnonymousInnerClass : EACSignatureVerifier
		{
			private readonly JcaEACSignatureVerifierBuilder outerInstance;

			private ASN1ObjectIdentifier usageOid;
			private NoSuchAlgorithmException e;
			private JcaEACSignatureVerifierBuilder.SignatureOutputStream sigStream;

			public EACSignatureVerifierAnonymousInnerClass(JcaEACSignatureVerifierBuilder outerInstance, ASN1ObjectIdentifier usageOid, NoSuchAlgorithmException e, JcaEACSignatureVerifierBuilder.SignatureOutputStream sigStream)
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

			public bool verify(byte[] expected)
			{
				try
				{
					if (usageOid.on(EACObjectIdentifiers_Fields.id_TA_ECDSA))
					{
						try
						{
							byte[] reencoded = derEncode(expected);

							return sigStream.verify(reencoded);
						}
						catch (Exception)
						{
							return false;
						}
					}
					else
					{
						return sigStream.verify(expected);
					}
				}
				catch (SignatureException e)
				{
					throw new RuntimeOperatorException("exception obtaining signature: " + e.Message, e);
				}
			}
		}

		private static byte[] derEncode(byte[] rawSign)
		{
			int len = rawSign.Length / 2;

			byte[] r = new byte[len];
			byte[] s = new byte[len];
			JavaSystem.arraycopy(rawSign, 0, r, 0, len);
			JavaSystem.arraycopy(rawSign, len, s, 0, len);

			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(new ASN1Integer(new BigInteger(1, r)));
			v.add(new ASN1Integer(new BigInteger(1, s)));

			DERSequence seq = new DERSequence(v);
			return seq.getEncoded();
		}

		public class SignatureOutputStream : OutputStream
		{
			private readonly JcaEACSignatureVerifierBuilder outerInstance;

			internal Signature sig;

			public SignatureOutputStream(JcaEACSignatureVerifierBuilder outerInstance, Signature sig)
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

			public virtual bool verify(byte[] expected)
			{
				return sig.verify(expected);
			}
		}
	}

}