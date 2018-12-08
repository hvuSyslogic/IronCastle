using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using OCSPResponse = org.bouncycastle.asn1.ocsp.OCSPResponse;

	public class CertificateStatus
	{
		protected internal short statusType;
		protected internal object response;

		public CertificateStatus(short statusType, object response)
		{
			if (!isCorrectType(statusType, response))
			{
				throw new IllegalArgumentException("'response' is not an instance of the correct type");
			}

			this.statusType = statusType;
			this.response = response;
		}

		public virtual short getStatusType()
		{
			return statusType;
		}

		public virtual object getResponse()
		{
			return response;
		}

		public virtual OCSPResponse getOCSPResponse()
		{
			if (!isCorrectType(CertificateStatusType.ocsp, response))
			{
				throw new IllegalStateException("'response' is not an OCSPResponse");
			}
			return (OCSPResponse)response;
		}

		/// <summary>
		/// Encode this <seealso cref="CertificateStatus"/> to an <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output">
		///            the <seealso cref="OutputStream"/> to encode to. </param>
		/// <exception cref="IOException"> </exception>
		public virtual void encode(OutputStream output)
		{
			TlsUtils.writeUint8(statusType, output);

			switch (statusType)
			{
			case CertificateStatusType.ocsp:
				byte[] derEncoding = ((OCSPResponse) response).getEncoded(ASN1Encoding_Fields.DER);
				TlsUtils.writeOpaque24(derEncoding, output);
				break;
			default:
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		/// <summary>
		/// Parse a <seealso cref="CertificateStatus"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="CertificateStatus"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static CertificateStatus parse(InputStream input)
		{
			short status_type = TlsUtils.readUint8(input);
			object response;

			switch (status_type)
			{
			case CertificateStatusType.ocsp:
			{
				byte[] derEncoding = TlsUtils.readOpaque24(input);
				response = OCSPResponse.getInstance(TlsUtils.readDERObject(derEncoding));
				break;
			}
			default:
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			return new CertificateStatus(status_type, response);
		}

		protected internal static bool isCorrectType(short statusType, object response)
		{
			switch (statusType)
			{
			case CertificateStatusType.ocsp:
				return response is OCSPResponse;
			default:
				throw new IllegalArgumentException("'statusType' is an unsupported CertificateStatusType");
			}
		}
	}

}