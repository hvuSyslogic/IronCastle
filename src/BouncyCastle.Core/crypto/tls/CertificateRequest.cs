using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	/// <summary>
	/// Parsing and encoding of a <i>CertificateRequest</i> struct from RFC 4346.
	/// <pre>
	/// struct {
	///     ClientCertificateType certificate_types&lt;1..2^8-1&gt;
	///     DistinguishedName certificate_authorities&lt;3..2^16-1&gt;
	/// } CertificateRequest;
	/// </pre>
	/// </summary>
	/// <seealso cref= ClientCertificateType </seealso>
	/// <seealso cref= X500Name </seealso>
	public class CertificateRequest
	{
		protected internal short[] certificateTypes;
		protected internal Vector supportedSignatureAlgorithms;
		protected internal Vector certificateAuthorities;

		/// <param name="certificateTypes">       see <seealso cref="ClientCertificateType"/> for valid constants. </param>
		/// <param name="certificateAuthorities"> a <seealso cref="Vector"/> of <seealso cref="X500Name"/>. </param>
		public CertificateRequest(short[] certificateTypes, Vector supportedSignatureAlgorithms, Vector certificateAuthorities)
		{
			this.certificateTypes = certificateTypes;
			this.supportedSignatureAlgorithms = supportedSignatureAlgorithms;
			this.certificateAuthorities = certificateAuthorities;
		}

		/// <returns> an array of certificate types </returns>
		/// <seealso cref= ClientCertificateType </seealso>
		public virtual short[] getCertificateTypes()
		{
			return certificateTypes;
		}

		/// <returns> a <seealso cref="Vector"/> of <seealso cref="SignatureAndHashAlgorithm"/> (or null before TLS 1.2). </returns>
		public virtual Vector getSupportedSignatureAlgorithms()
		{
			return supportedSignatureAlgorithms;
		}

		/// <returns> a <seealso cref="Vector"/> of <seealso cref="X500Name"/> </returns>
		public virtual Vector getCertificateAuthorities()
		{
			return certificateAuthorities;
		}

		/// <summary>
		/// Encode this <seealso cref="CertificateRequest"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output"> the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			if (certificateTypes == null || certificateTypes.Length == 0)
			{
				TlsUtils.writeUint8(0, output);
			}
			else
			{
				TlsUtils.writeUint8ArrayWithUint8Length(certificateTypes, output);
			}

			if (supportedSignatureAlgorithms != null)
			{
				// TODO Check whether SignatureAlgorithm.anonymous is allowed here
				TlsUtils.encodeSupportedSignatureAlgorithms(supportedSignatureAlgorithms, false, output);
			}

			if (certificateAuthorities == null || certificateAuthorities.isEmpty())
			{
				TlsUtils.writeUint16(0, output);
			}
			else
			{
				Vector derEncodings = new Vector(certificateAuthorities.size());

				int totalLength = 0;
				for (int i = 0; i < certificateAuthorities.size(); ++i)
				{
					X500Name certificateAuthority = (X500Name)certificateAuthorities.elementAt(i);
					byte[] derEncoding = certificateAuthority.getEncoded(ASN1Encoding_Fields.DER);
					derEncodings.addElement(derEncoding);
					totalLength += derEncoding.Length + 2;
				}

				TlsUtils.checkUint16(totalLength);
				TlsUtils.writeUint16(totalLength, output);

				for (int i = 0; i < derEncodings.size(); ++i)
				{
					byte[] derEncoding = (byte[])derEncodings.elementAt(i);
					TlsUtils.writeOpaque16(derEncoding, output);
				}
			}
		}

		/// <summary>
		/// Parse a <seealso cref="CertificateRequest"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="context">
		///            the <seealso cref="TlsContext"/> of the current connection. </param>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="CertificateRequest"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static CertificateRequest parse(TlsContext context, InputStream input)
		{
			int numTypes = TlsUtils.readUint8(input);
			short[] certificateTypes = new short[numTypes];
			for (int i = 0; i < numTypes; ++i)
			{
				certificateTypes[i] = TlsUtils.readUint8(input);
			}

			Vector supportedSignatureAlgorithms = null;
			if (TlsUtils.isTLSv12(context))
			{
				// TODO Check whether SignatureAlgorithm.anonymous is allowed here
				supportedSignatureAlgorithms = TlsUtils.parseSupportedSignatureAlgorithms(false, input);
			}

			Vector certificateAuthorities = new Vector();
			byte[] certAuthData = TlsUtils.readOpaque16(input);
			ByteArrayInputStream bis = new ByteArrayInputStream(certAuthData);
			while (bis.available() > 0)
			{
				byte[] derEncoding = TlsUtils.readOpaque16(bis);
				ASN1Primitive asn1 = TlsUtils.readDERObject(derEncoding);
				certificateAuthorities.addElement(X500Name.getInstance(asn1));
			}

			return new CertificateRequest(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities);
		}
	}

}