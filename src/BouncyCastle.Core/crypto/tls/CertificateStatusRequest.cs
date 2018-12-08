using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	public class CertificateStatusRequest
	{
		protected internal short statusType;
		protected internal object request;

		public CertificateStatusRequest(short statusType, object request)
		{
			if (!isCorrectType(statusType, request))
			{
				throw new IllegalArgumentException("'request' is not an instance of the correct type");
			}

			this.statusType = statusType;
			this.request = request;
		}

		public virtual short getStatusType()
		{
			return statusType;
		}

		public virtual object getRequest()
		{
			return request;
		}

		public virtual OCSPStatusRequest getOCSPStatusRequest()
		{
			if (!isCorrectType(CertificateStatusType.ocsp, request))
			{
				throw new IllegalStateException("'request' is not an OCSPStatusRequest");
			}
			return (OCSPStatusRequest)request;
		}

		/// <summary>
		/// Encode this <seealso cref="CertificateStatusRequest"/> to an <seealso cref="OutputStream"/>.
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
				((OCSPStatusRequest) request).encode(output);
				break;
			default:
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		/// <summary>
		/// Parse a <seealso cref="CertificateStatusRequest"/> from an <seealso cref="InputStream"/>.
		/// </summary>
		/// <param name="input">
		///            the <seealso cref="InputStream"/> to parse from. </param>
		/// <returns> a <seealso cref="CertificateStatusRequest"/> object. </returns>
		/// <exception cref="IOException"> </exception>
		public static CertificateStatusRequest parse(InputStream input)
		{
			short status_type = TlsUtils.readUint8(input);
			object result;

			switch (status_type)
			{
			case CertificateStatusType.ocsp:
				result = OCSPStatusRequest.parse(input);
				break;
			default:
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			return new CertificateStatusRequest(status_type, result);
		}

		protected internal static bool isCorrectType(short statusType, object request)
		{
			switch (statusType)
			{
			case CertificateStatusType.ocsp:
				return request is OCSPStatusRequest;
			default:
				throw new IllegalArgumentException("'statusType' is an unsupported CertificateStatusType");
			}
		}
	}

}