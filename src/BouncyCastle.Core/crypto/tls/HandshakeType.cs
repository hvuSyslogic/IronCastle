namespace org.bouncycastle.crypto.tls
{
	public class HandshakeType
	{
		/*
		 * RFC 2246 7.4
		 */
		public const short hello_request = 0;
		public const short client_hello = 1;
		public const short server_hello = 2;
		public const short certificate = 11;
		public const short server_key_exchange = 12;
		public const short certificate_request = 13;
		public const short server_hello_done = 14;
		public const short certificate_verify = 15;
		public const short client_key_exchange = 16;
		public const short finished = 20;

		/*
		 * RFC 3546 2.4
		 */
		public const short certificate_url = 21;
		public const short certificate_status = 22;

		/*
		 *  (DTLS) RFC 4347 4.3.2
		 */
		public const short hello_verify_request = 3;

		/*
		 * RFC 4680 
		 */
		public const short supplemental_data = 23;

		/*
		 * RFC 5077 
		 */
		public const short session_ticket = 4;
	}

}