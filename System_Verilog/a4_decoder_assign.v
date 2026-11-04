// 2-to-4 decoder with enable, continuous assignments
module decoder_assign(en, a, b, y);
    input en, a, b;
    output [3:0] y;
    assign y[0] = en & ~a & ~b;
    assign y[1] = en & ~a &  b;
    assign y[2] = en &  a & ~b;
    assign y[3] = en &  a &  b;
endmodule

module main();
    reg en, a, b;
    wire [3:0] y;
    integer i;

    decoder_assign d1(en, a, b, y);

    initial
    begin
        $monitor("en=%b a=%b b=%b -> y=%b", en, a, b, y);
        for (i = 0; i < 8; i = i + 1)
        begin
            {en, a, b} = i;
            #5;
        end
    end
endmodule

//Developed with assistance from Claude (AI assistant by Anthropic)
