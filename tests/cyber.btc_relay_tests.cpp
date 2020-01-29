#include <boost/test/unit_test.hpp>
#include <eosio/testing/tester.hpp>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/wast_to_wasm.hpp>

#include <Runtime/Runtime.h>

#include <fc/variant_object.hpp>
#include "contracts.hpp"
#include "cyber.btc_relay_test_api.hpp"
#include "btc_data/blocks_449569_449717.h"
#include "btc_data/blocks_604801_606819.h"

using namespace eosio::testing;
using namespace eosio;
using namespace eosio::chain;
using namespace eosio::testing;
using namespace fc;

using mvo = fc::mutable_variant_object;

class cyber_btc_relay_tester : public golos_tester {
protected:
    cyber_btc_relay_api btc_relay;
    btc_block_header init_header;
    vector<string> headers_hex;
    string init_hash;
    string next_hash;
    string first_tx;
    vector<string> first_siblings;
    static const int64_t init_height = 604800;
    
public:
    cyber_btc_relay_tester()
    : golos_tester(cyber::config::btc_relay_name, false)
    , btc_relay(this, cyber::config::btc_relay_name) {
        init_hash = "00000000000000000012145f8ffa7218d2d04ca66b61835a2a5eaec33dffc098";
        next_hash = "0000000000000000001547af651cb72a71c7e6841e3ecafad8707e2b7f23c0f5";
        
        first_tx = "01000000012929d9190bd30c2af7c6909cf75c8d236bf695875bc74747c687055755cbf56f01000000fdfd0000483045022100e11a1b00f11"
                   "a2413b565b83c8867010c04208f483e86697d2095dc19c4a7f478022071b018d321e8d558841882483eabd06845cabeec6000c3410c7e7c59"
                   "6d11c12c0147304402204d7a54c567393a57bf5f1302e28fa9068033b1bf0ea71f82e8ead4630c27918b02201ead4f0266fe5cdb320b70965"
                   "0a4cac17edfcf2da5589154a5a8c0dfef0f1532014c69522103686065662de7c39dcc2e1d07a1c9647de6dcb9d842ea34a3e6c1241a7023b9"
                   "052103d5c210db83ce2141fff3ad75b792ea01b0913f64ae63067a91676c8a9019d5872103494892fe34b50ea031eae99674f83a6e74b8ddf"
                   "4954cae7787e88ee4b022775153aeffffffff02a08601000000000017a9142c14071f5367d59325182ed204fcd7b37b74f04d87bf29010000"
                   "00000017a91404abbe89f71ac7b0a1482bf17cea149a0a368b358700000000";
        first_siblings = vector<string>{
            "19f4b1c731ffbc142328def69fc2127c4b70107a9d77949f51cb30e19ecc2a88", 
            "f824c64693cbb70b4e3c66e22669dbc916c45d9e082154e555262c99ca0bb810",
            "b54ec0b25ad99c78c3225b403a93b9be0ae94a3b1d9a0caa9fc2aef6593d1d61", 
            "296841f81d4ad9b8195b696d1b171301c8f4c36c7aecba020edcd6becfae625f", 
            "2914c6f84fcc72f434c1b6d4eebf62f2f7db385894b6f07c2c2210e7c0e59e52",
            "d2cfbc96c9a15e752ce3118c8c619fbe3a947c963b5ee75613a9eb5ae790841e", 
            "80ce8f854718dfdd8badd651b0d68ec13fcb8052e9659b9dd9bd5594158c8cd8",
            "76812b0bc66e5b5d7bb09a72f3c1102529726e0727f89fe27e3a3d28318c384f",
            "ecc6794e71e863e328209f9183a3a5fa212c4ca472c666ae348c16edd015b091", 
            "f3cc147fed9dd7cb9484704c34e1754d8456fdfd4ed4f56ea1f8d3f3aaed2f12", 
            "3e89eb70e03ee06f601bae49799cae770817635d24a94af6916e8b70ce7c7e92", 
            "efc2819f943af092a5520aefcb059efa17cd6c6276f0744a040a4a4f01dd7bb4"};
        
        init_header.version = 0x20000000;
        init_header.prev_hash = "00000000000000000002fb021eeb13e47021920faf6e5daa3c40bc552c4d248e";
        init_header.merkle_root = "6a6df0960d18625f5bf791f367149fa933c435ffb20ba232b28d2df79d4d3be0";
        init_header.time = 1574356132;
        init_header.bits = 0x1715b23e;
        init_header.nonce = 857143710;
        
        headers_hex.emplace_back("00c0ff3f98c0ff3dc3ae5e2a5a83616ba64cd0d21872fa8f5f141200000000000000000091396ed1"
                                 "d90263898fc6fc1d4ea478eaea6e044ac49bcdc1ecf77915d366fbe4c1c5d65d3eb21517ed831602");
        headers_hex.emplace_back("00000020f5c0237f2b7e70d8faca3e1e84e6c7712ab71c65af471500000000000000000075cae461"
                                 "f023cee29062c8cd60a26aa797ef4f0783fa6337461ced89c14154d3e9c6d65d3eb215174c33b8e4");
        create_accounts({cyber::config::btc_relay_name, N(alice), N(bob), N(carol)});
        produce_block();
        install_contract(cyber::config::btc_relay_name, contracts::btc_relay_wasm(), contracts::btc_relay_abi());
        produce_block();
    }
    
    size_t add_blocks_from_vec(const vector<string>& headers) {
        size_t ret = 0;
        for (const auto h : headers) {
            BOOST_CHECK_EQUAL(success(), btc_relay.addheaderhex(h, N(alice)));
            if ((++ret) % 20 == 0) {
                produce_block();
            }
        }
        return ret;
    }
    
    struct errors: contract_error_messages {
        const string wrong_init_adj_interval    = amsg("initial block should be the first in the difficulty adjustment interval");
        const string already_init               = amsg("already initialized");
        const string pow_error                  = amsg("PoW error");
        const string already_added              = amsg("already added");
        const string no_previous                = amsg("no previous block");
        const string not_initialized            = amsg("relay not initialized");
        const string no_block                   = amsg("block not found");
        const string no_proof                   = amsg("failed to prove transaction existence in block");
        const string insufficient_confirmations = amsg("insufficient transaction confirmations");
        const string orphan                     = amsg("the block is not in the main chain");
        
        const string unsupported_address         = amsg("unsupported address");
        const string base58_checksum             = amsg("base58 checksum mismatch");
        const string bech32_checksum             = amsg("bech32 checksum mismatch");
        const string insufficient_payment        = amsg("insufficient payment");
        const string invalid_symbol              = amsg("invalid symbol name or precision");
        const string neg_quantity                = amsg("must require positive quantity");
        const string incorrect_segwit_flag       = amsg("incorrect segwit flag");
        const string unexpected_end_of_tx        = amsg("unexpected end of transaction data");
        const string no_payment                  = amsg("payment not found");
    } err;
};

BOOST_AUTO_TEST_SUITE(cyber_btc_relay_tests)

BOOST_FIXTURE_TEST_CASE(init_test, cyber_btc_relay_tester) try {
    BOOST_TEST_MESSAGE("btc_relay/init_test");
    BOOST_CHECK_EQUAL(err.wrong_init_adj_interval, btc_relay.init(init_header, init_height+1));
    init_header.nonce += 1;
    BOOST_CHECK_EQUAL(err.pow_error, btc_relay.init(init_header, init_height));
    init_header.nonce -= 1;
    BOOST_CHECK_EQUAL(success(), btc_relay.init(init_header, init_height));
    produce_block();
    BOOST_CHECK_EQUAL(err.already_init, btc_relay.init(init_header, init_height));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(addheader_test, cyber_btc_relay_tester) try {
    BOOST_TEST_MESSAGE("btc_relay/addheader_test");
    
    btc_block_header header1;
    header1.version = 0x3fffc000;
    header1.prev_hash = init_header.merkle_root;
    header1.merkle_root = "e4fb66d31579f7ecc1cd9bc44a046eeaea78a44e1dfcc68f896302d9d16e3991";
    header1.time = 1574356417;
    header1.bits = init_header.bits;
    header1.nonce = 35029997;
    BOOST_CHECK_EQUAL(err.not_initialized, btc_relay.addheader(header1, N(alice)));
    BOOST_CHECK_EQUAL(success(), btc_relay.init(init_header, init_height));
    
    BOOST_CHECK_EQUAL(err.no_previous, btc_relay.addheader(header1, N(alice)));
    header1.prev_hash = init_header.prev_hash;
    BOOST_CHECK_EQUAL(err.no_previous, btc_relay.addheader(header1, N(alice)));
    header1.prev_hash = init_hash;
    header1.nonce += 1;
    BOOST_CHECK_EQUAL(err.pow_error, btc_relay.addheader(header1, N(alice)));
    header1.nonce -= 1;
    BOOST_CHECK_EQUAL(success(), btc_relay.addheader(header1, N(alice)));
    
    BOOST_CHECK_EQUAL(err.already_added, btc_relay.addheaderhex(headers_hex[0], N(alice)));
    BOOST_CHECK_EQUAL(success(), btc_relay.addheaderhex(headers_hex[1], N(alice)));
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(verifytx_test, cyber_btc_relay_tester) try {
    BOOST_TEST_MESSAGE("btc_relay/verifytx_test");
    BOOST_CHECK_EQUAL(success(), btc_relay.init(init_header, init_height));
    auto wrong_siblings = first_siblings;
    wrong_siblings[0][0] = 'f';
    string wrong_tx = first_tx;
    wrong_tx[0] = 'f';
    
    BOOST_CHECK_EQUAL(err.no_block, btc_relay.verifytx(first_tx, 1, first_siblings, next_hash, 1));
    
    BOOST_CHECK_EQUAL(err.no_proof, btc_relay.verifytx(wrong_tx, 1, first_siblings, init_hash, 1));
    BOOST_CHECK_EQUAL(err.no_proof, btc_relay.verifytx(wrong_tx, 1, wrong_siblings, init_hash, 1));
    BOOST_CHECK_EQUAL(err.no_proof, btc_relay.verifytx(first_tx, 1, wrong_siblings, init_hash, 1));
    BOOST_CHECK_EQUAL(err.no_proof, btc_relay.verifytx(first_tx, 2, first_siblings, init_hash, 1));
    
    BOOST_CHECK_EQUAL(success(), btc_relay.verifytx(first_tx, 1, first_siblings, init_hash, 1));
    
    BOOST_CHECK_EQUAL(err.insufficient_confirmations, btc_relay.verifytx(first_tx, 1, first_siblings, init_hash, 3));
    BOOST_CHECK_EQUAL(success(), btc_relay.addheaderhex(headers_hex[0], N(alice)));
    
    BOOST_CHECK_EQUAL(err.no_proof, btc_relay.verifytx(first_tx, 1, first_siblings, next_hash, 1));
    
    BOOST_CHECK_EQUAL(success(), btc_relay.verifytx(first_tx, 1, first_siblings, init_hash, 2));
    BOOST_CHECK_EQUAL(err.insufficient_confirmations, btc_relay.verifytx(first_tx, 1, first_siblings, init_hash, 3));
    BOOST_CHECK_EQUAL(success(), btc_relay.addheaderhex(headers_hex[1], N(alice)));
    
    BOOST_CHECK_EQUAL(success(), btc_relay.verifytx(first_tx, 1, first_siblings, init_hash, 3));
    
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(many_blocks_test, cyber_btc_relay_tester) try {
    BOOST_TEST_MESSAGE("btc_relay/many_blocks_test");
    BOOST_CHECK_EQUAL(success(), btc_relay.init(init_header, init_height));
    auto i = add_blocks_from_vec(blocks_604801_606819);
    BOOST_CHECK_EQUAL(i, 2019);
    BOOST_CHECK_EQUAL(success(), btc_relay.verifytx(first_tx, 1, first_siblings, init_hash, 2020));
    BOOST_CHECK_EQUAL(err.insufficient_confirmations, btc_relay.verifytx(first_tx, 1, first_siblings, init_hash, 2021));
    
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(orphan_block_tx_test, cyber_btc_relay_tester) try {
    
    BOOST_TEST_MESSAGE("btc_relay/orphan_block_tx_test");
    int64_t pre_orphan_init_height = 449568;
    
    btc_block_header pre_orphan_init_header;
    pre_orphan_init_header.version = 0x20000000;
    pre_orphan_init_header.prev_hash = "000000000000000000cb26d2b1018d80670ccc41d89c7da92175bd6b00f27a3e";
    pre_orphan_init_header.merkle_root = "67242fa3f424d1b9148cbba2e307ac21da36b37f4d8f0e32f8c05636370bb88d";
    pre_orphan_init_header.time = 1485125572;
    pre_orphan_init_header.bits = 0x1802cc47;
    pre_orphan_init_header.nonce = 1292081531;
    
    string orphan_hash = "0000000000000000001a5db47750928e1cfb94ee03ed88b0343c7d1cf6387f9a"; //height = 449695
    
    BOOST_CHECK_EQUAL(success(), btc_relay.init(pre_orphan_init_header, pre_orphan_init_height));
    
    add_blocks_from_vec(blocks_449569_449717);
    
    //merkle proof does not matter, because block check occurs earlier
    BOOST_CHECK_EQUAL(err.orphan, btc_relay.verifytx("blabla", 1, first_siblings, orphan_hash, 1));
    
} FC_LOG_AND_RETHROW()

BOOST_FIXTURE_TEST_CASE(checkpayment_test, cyber_btc_relay_tester) try {
    BOOST_TEST_MESSAGE("btc_relay/checkpayment_test");

    BOOST_CHECK_EQUAL(err.invalid_symbol, btc_relay.checkpayment(first_tx, "35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUe", asset(1, eosio::chain::symbol(8, "BCH"))));
    BOOST_CHECK_EQUAL(err.invalid_symbol, btc_relay.checkpayment(first_tx, "35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUe", asset(1, eosio::chain::symbol(7, "BTC"))));
    BOOST_CHECK_EQUAL(err.neg_quantity, btc_relay.checkpayment(first_tx, "35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUe", asset(0, eosio::chain::symbol(8, "BTC"))));
    BOOST_CHECK_EQUAL(err.incorrect_segwit_flag, btc_relay.checkpayment("0100000000020152", "35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUe", asset(1, btc_symbol)));
    BOOST_CHECK_EQUAL(err.unexpected_end_of_tx, btc_relay.checkpayment(
        "010000000106d204ff267a545207bb87407a32", "35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUe", asset(1, btc_symbol)));
    BOOST_CHECK_EQUAL(err.no_payment, btc_relay.checkpayment(first_tx, "1PBQSn66w6nDtP1NMcDiGwiLqYhe6LqnN3", asset(1, btc_symbol)));
        
    BOOST_CHECK_EQUAL(err.unsupported_address, btc_relay.checkaddress("35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUxxx"));
    BOOST_CHECK_EQUAL(err.base58_checksum, btc_relay.checkaddress("35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUx"));
    BOOST_CHECK_EQUAL(success(), btc_relay.checkaddress("35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUe"));
    BOOST_CHECK_EQUAL(success(), btc_relay.checkpayment(first_tx, "35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUe", asset(100000, btc_symbol)));
    BOOST_CHECK_EQUAL(err.insufficient_payment, btc_relay.checkpayment(first_tx, "35i5eYNg9ue7SAQvpAoXEabiDQ5FATuxUe", asset(100001, btc_symbol)));
    
    //block 604800, tx 8e8f2c8061530ddd6a308b57f9e272f267e1c2861fe6482bf8696c911a396b88
    BOOST_CHECK_EQUAL(success(), btc_relay.checkpayment(
        "010000000106d204ff267a545207bb87407a3235bdebbbfca903728ae11292dbf5cdf1a8f8000000006b483045022100bec6dccc5d31f5aa40b43a8c42ec0c49af14"
        "656da34078048c4b1e4b4bba208c0220750ca3183381a9993a583187aef8cfdc0c73150613532dc96d1e5da744256435012103cd0bb85056ef4657c822340207f25c"
        "05edf373bb572e9692c3342906076cc0eaffffffff018a8d0300000000001976a914f34a7f4e85f52385a00deb6ac774b8f0b802be7488ac00000000",
        "1PBQSn66w6nDtP1NMcDiGwiLqYhe6LqnN3", asset(232842, btc_symbol)));
    
    BOOST_CHECK_EQUAL(err.insufficient_payment, btc_relay.checkpayment(
        "010000000106d204ff267a545207bb87407a3235bdebbbfca903728ae11292dbf5cdf1a8f8000000006b483045022100bec6dccc5d31f5aa40b43a8c42ec0c49af14"
        "656da34078048c4b1e4b4bba208c0220750ca3183381a9993a583187aef8cfdc0c73150613532dc96d1e5da744256435012103cd0bb85056ef4657c822340207f25c"
        "05edf373bb572e9692c3342906076cc0eaffffffff018a8d0300000000001976a914f34a7f4e85f52385a00deb6ac774b8f0b802be7488ac00000000",
        "1PBQSn66w6nDtP1NMcDiGwiLqYhe6LqnN3", asset(232843, btc_symbol)));
    
    //block 604800, tx a6ab306fa7ab48bb8114dbc768a88ecc1d39da0d24e57c8fde6de47651777a37
    BOOST_CHECK_EQUAL(err.bech32_checksum, btc_relay.checkaddress("bc1qhnfpy3mfuh8cfkem6umlcd9m9ect6xwk22f838"));
    BOOST_CHECK_EQUAL(success(), btc_relay.checkpayment(
        "01000000000101d29bbe135a728658db011358a61811ecdb287382bf41edfcc5382653e8de34050000000017160014e83b6d27abbca780ad6663773c3b15be477e3dc1"
        "fdffffff017c9f570700000000160014bcd2124769e5cf84db3bd737fc34bb2e70bd19d602483045022100e5e8516c64cd9f0bc4edb90087b5d18fccc0be1b29761d93"
        "3e1f0818e97c5a340220176991654d674608cdc84bd49c928c4a391beaaa40a42e3489e3b8e604d596520121025322c9bd2f7b47c95a55a779e72ceafb51c926e80cce"
        "505946e48f3345da21ce00000000",
        "bc1qhnfpy3mfuh8cfkem6umlcd9m9ect6xwk22f839", asset(123182972, btc_symbol)));
        
    BOOST_CHECK_EQUAL(err.insufficient_payment, btc_relay.checkpayment(
        "01000000000101d29bbe135a728658db011358a61811ecdb287382bf41edfcc5382653e8de34050000000017160014e83b6d27abbca780ad6663773c3b15be477e3dc1"
        "fdffffff017c9f570700000000160014bcd2124769e5cf84db3bd737fc34bb2e70bd19d602483045022100e5e8516c64cd9f0bc4edb90087b5d18fccc0be1b29761d93"
        "3e1f0818e97c5a340220176991654d674608cdc84bd49c928c4a391beaaa40a42e3489e3b8e604d596520121025322c9bd2f7b47c95a55a779e72ceafb51c926e80cce"
        "505946e48f3345da21ce00000000",
        "bc1qhnfpy3mfuh8cfkem6umlcd9m9ect6xwk22f839", asset(123182973, btc_symbol)));
    
    //block 604800, tx ecbd68f5dc269b80b09ef994bdafd8e620a2487840999b2bc675131cc7b4feba
    BOOST_CHECK_EQUAL(success(), btc_relay.checkpayment(
        "0100000000010152c355b7963285655ddcc278a65c370221f8e92d370d6debe061b6e507feb3530100000000ffffffff0200e1f5050000000017a9149f7f95e742b3f"
        "3c4df144856f599d1a28799dcff87e8a3de0300000000220020299118f6de2b7cf88acb436cc238acdc652eeedd2d925cbaa51a54b27a7974de04004730440220172c"
        "ec76dd43f5d0ca1c0225f44372e58730ce0c433258417337aae16ddbb8ab022045bbce3d65912912c8812be9fb1fb9c551b225ebee599ffce4f4c702bf35fbf201473"
        "044022072cb81063e1a77f20f8bfd5c2a5241e5fead9056f02b9ba83dc3e72ddbd26b6102205bbe9e78a465ba9ad7ee2e76fd0ee8937bfb9858ad22088c057d6d16d8"
        "de8b5701695221021ab1044a2f7d38c7f224fd4fef3eeae38f237fa29424c9a37bbb940690af11b0210236a12b50ed39400b4990e658d4e0d4c038c2dee081d05a606"
        "4264691edb443ef2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
        "bc1q9xg33ak79d703zktgdkvyw9vm3jjamka9kf9ew49rf2ty7newn0qwa5hzs", asset(64922600, btc_symbol)));
    
    BOOST_CHECK_EQUAL(err.insufficient_payment, btc_relay.checkpayment(
        "0100000000010152c355b7963285655ddcc278a65c370221f8e92d370d6debe061b6e507feb3530100000000ffffffff0200e1f5050000000017a9149f7f95e742b3f"
        "3c4df144856f599d1a28799dcff87e8a3de0300000000220020299118f6de2b7cf88acb436cc238acdc652eeedd2d925cbaa51a54b27a7974de04004730440220172c"
        "ec76dd43f5d0ca1c0225f44372e58730ce0c433258417337aae16ddbb8ab022045bbce3d65912912c8812be9fb1fb9c551b225ebee599ffce4f4c702bf35fbf201473"
        "044022072cb81063e1a77f20f8bfd5c2a5241e5fead9056f02b9ba83dc3e72ddbd26b6102205bbe9e78a465ba9ad7ee2e76fd0ee8937bfb9858ad22088c057d6d16d8"
        "de8b5701695221021ab1044a2f7d38c7f224fd4fef3eeae38f237fa29424c9a37bbb940690af11b0210236a12b50ed39400b4990e658d4e0d4c038c2dee081d05a606"
        "4264691edb443ef2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
        "bc1q9xg33ak79d703zktgdkvyw9vm3jjamka9kf9ew49rf2ty7newn0qwa5hzs", asset(64922601, btc_symbol)));

} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()
