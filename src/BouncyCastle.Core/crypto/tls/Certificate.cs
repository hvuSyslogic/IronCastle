using System.IO;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

		
	/// <summary>
	/// Parsing and encoding of a <i>Certificate</i> struct from RFC 4346.
	/// <pre>
	/// opaque ASN.1Cert&lt;2^24-1&gt;
	/// 
	/// struct {
	///     ASN.1Cert certificate_list&lt;0..2^24-1&gt;
	/// } Certificate;
	/// </pre>
	/// </summary>
	/// <seealso cref= org.bouncycastle.asn1.x509.Certificate </seealso>
	public class Certificate
	{
		public static readonly Certificate EMPTY_CHAIN = new Certificate(new org.bouncycastle.asn1.x509.Certificate[0]);

		protected internal org.bouncycastle.asn1.x509.Certificate[] certificateList;

		public Certificate(org.bouncycastle.asn1.x509.Certificate[] certificateList)
		{
			if (certificateList == null)
			{
				throw new IllegalArgumentException("'certificateList' cannot be null");
			}

			this.certificateList = certificateList;
		}

		/// <returns> an array of <seealso cref="org.bouncycastle.asn1.x509.Certificate"/> representing a certificate
		///         chain. </returns>
		public virtual org.bouncycastle.asn1.x509.Certificate[] getCertificateList()
		{
			return cloneCertificateList();
		}

		public virtual org.bouncycastle.asn1.x509.Certificate getCertificateAt(int index)
		{
			return certificateList[index];
		}

		public virtual int getLength()
		{
			return certificateList.Length;
		}

		/// <returns> <code>true</code> if this certificate chain contains no certificates, or
		///         <code>false</code> otherwise. </returns>
		public virtual bool isEmpty()
		{
			return certificateList.Length == 0;
		}

		/// <summary>
		/// Encode this <seealso cref="Certificate"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output"> the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			Vector derEncodings = new Vector(this.certificateList.Length);

			int totalLength = 0;
			for (int i = 0; i < this.certificateList.Length; ++i)
			{
				byte[] derEncoding = certificateList[i].getEncoded(ASN1Encoding_Fields.DER);
				derEncodings.addElement(derEncoding);
				totalLength += derEncoding.Length + 3;
			}

			TlsUtils.checkUint24(totalLength);
			TlsUtils.writeUint24(totalLength, output);

			for (int i = 0; i < derEncodings.size(); ++i)
			{
				byte[] derEncoding = (byte[])derEncodings.elementAt(i);
				TlsUtils.writeOpaque24(derEncoding, output);
			}
		}

		/// <summary>
		/// Parse a <seealso cref="Certificate"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input"> the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="Certificate"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static Certificate parse(InputStream input)
		{
			int totalLength = TlsUtils.readUint24(input);
			if (totalLength == 0)
			{
				return EMPTY_CHAIN;
			}

			byte[] certListData = TlsUtils.readFully(totalLength, input);

			ByteArrayInputStream buf = new ByteArrayInputStream(certListData);

			Vector certificate_list = new Vector();
			while (buf.available() > 0)
			{
				byte[] berEncoding = TlsUtils.readOpaque24(buf);
				ASN1Primitive asn1Cert = TlsUtils.readASN1Object(berEncoding);
				certificate_list.addElement(org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert));
			}

		    org.bouncycastle.asn1.x509.Certificate[] certificateList = new org.bouncycastle.asn1.x509.Certificate[certificate_list.size()];
			for (int i = 0; i < certificate_list.size(); i++)
			{
				certificateList[i] = (org.bouncycastle.asn1.x509.Certificate)certificate_list.elementAt(i);
			}
			return new Certificate(certificateList);
		}

		public virtual org.bouncycastle.asn1.x509.Certificate[] cloneCertificateList()
		{
		    org.bouncycastle.asn1.x509.Certificate[] result = new org.bouncycastle.asn1.x509.Certificate[certificateList.Length];
			JavaSystem.arraycopy(certificateList, 0, result, 0, result.Length);
			return result;
		}
	}

}