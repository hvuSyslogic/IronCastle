using org.bouncycastle.asn1.cmp;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cert.cmp
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using CMPCertificate = org.bouncycastle.asn1.cmp.CMPCertificate;
	using CMPObjectIdentifiers = org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
	using PBMParameter = org.bouncycastle.asn1.cmp.PBMParameter;
	using PKIBody = org.bouncycastle.asn1.cmp.PKIBody;
	using PKIHeader = org.bouncycastle.asn1.cmp.PKIHeader;
	using PKIMessage = org.bouncycastle.asn1.cmp.PKIMessage;
	using PKMACBuilder = org.bouncycastle.cert.crmf.PKMACBuilder;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Wrapper for a PKIMessage with protection attached to it.
	/// </summary>
	public class ProtectedPKIMessage
	{
		private PKIMessage pkiMessage;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="pkiMessage"> a GeneralPKIMessage with </param>
		public ProtectedPKIMessage(GeneralPKIMessage pkiMessage)
		{
			if (!pkiMessage.hasProtection())
			{
				throw new IllegalArgumentException("PKIMessage not protected");
			}

			this.pkiMessage = pkiMessage.toASN1Structure();
		}

		public ProtectedPKIMessage(PKIMessage pkiMessage)
		{
			if (pkiMessage.getHeader().getProtectionAlg() == null)
			{
				throw new IllegalArgumentException("PKIMessage not protected");
			}

			this.pkiMessage = pkiMessage;
		}

		/// <summary>
		/// Return the message header.
		/// </summary>
		/// <returns> the message's PKIHeader structure. </returns>
		public virtual PKIHeader getHeader()
		{
			return pkiMessage.getHeader();
		}

		/// <summary>
		/// Return the message body.
		/// </summary>
		/// <returns> the message's PKIBody structure. </returns>
		public virtual PKIBody getBody()
		{
			return pkiMessage.getBody();
		}

		/// <summary>
		/// Return the underlying ASN.1 structure contained in this object.
		/// </summary>
		/// <returns> a PKIMessage structure. </returns>
		public virtual PKIMessage toASN1Structure()
		{
			return pkiMessage;
		}

		/// <summary>
		/// Determine whether the message is protected by a password based MAC. Use verify(PKMACBuilder, char[])
		/// to verify the message if this method returns true.
		/// </summary>
		/// <returns> true if protection MAC PBE based, false otherwise. </returns>
		public virtual bool hasPasswordBasedMacProtection()
		{
			return pkiMessage.getHeader().getProtectionAlg().getAlgorithm().Equals(CMPObjectIdentifiers_Fields.passwordBasedMac);
		}

		/// <summary>
		/// Return the extra certificates associated with this message.
		/// </summary>
		/// <returns> an array of extra certificates, zero length if none present. </returns>
		public virtual X509CertificateHolder[] getCertificates()
		{
			CMPCertificate[] certs = pkiMessage.getExtraCerts();

			if (certs == null)
			{
				return new X509CertificateHolder[0];
			}

			X509CertificateHolder[] res = new X509CertificateHolder[certs.Length];
			for (int i = 0; i != certs.Length; i++)
			{
				res[i] = new X509CertificateHolder(certs[i].getX509v3PKCert());
			}

			return res;
		}

		/// <summary>
		/// Verify a message with a public key based signature attached.
		/// </summary>
		/// <param name="verifierProvider"> a provider of signature verifiers. </param>
		/// <returns> true if the provider is able to create a verifier that validates
		/// the signature, false otherwise. </returns>
		/// <exception cref="CMPException"> if an exception is thrown trying to verify the signature. </exception>
		public virtual bool verify(ContentVerifierProvider verifierProvider)
		{
			ContentVerifier verifier;
			try
			{
				verifier = verifierProvider.get(pkiMessage.getHeader().getProtectionAlg());

				return verifySignature(pkiMessage.getProtection().getBytes(), verifier);
			}
			catch (Exception e)
			{
				throw new CMPException("unable to verify signature: " + e.Message, e);
			}
		}

		/// <summary>
		/// Verify a message with password based MAC protection.
		/// </summary>
		/// <param name="pkMacBuilder"> MAC builder that can be used to construct the appropriate MacCalculator </param>
		/// <param name="password"> the MAC password </param>
		/// <returns> true if the passed in password and MAC builder verify the message, false otherwise. </returns>
		/// <exception cref="CMPException"> if algorithm not MAC based, or an exception is thrown verifying the MAC. </exception>
		public virtual bool verify(PKMACBuilder pkMacBuilder, char[] password)
		{
			if (!CMPObjectIdentifiers_Fields.passwordBasedMac.Equals(pkiMessage.getHeader().getProtectionAlg().getAlgorithm()))
			{
				throw new CMPException("protection algorithm not mac based");
			}

			try
			{
				pkMacBuilder.setParameters(PBMParameter.getInstance(pkiMessage.getHeader().getProtectionAlg().getParameters()));
				MacCalculator calculator = pkMacBuilder.build(password);

				OutputStream macOut = calculator.getOutputStream();

				ASN1EncodableVector v = new ASN1EncodableVector();

				v.add(pkiMessage.getHeader());
				v.add(pkiMessage.getBody());

				macOut.write((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER));

				macOut.close();

				return Arrays.areEqual(calculator.getMac(), pkiMessage.getProtection().getBytes());
			}
			catch (Exception e)
			{
				throw new CMPException("unable to verify MAC: " + e.Message, e);
			}
		}

		private bool verifySignature(byte[] signature, ContentVerifier verifier)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(pkiMessage.getHeader());
			v.add(pkiMessage.getBody());

			OutputStream sOut = verifier.getOutputStream();

			sOut.write((new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER));

			sOut.close();

			return verifier.verify(signature);
		}
	}

}