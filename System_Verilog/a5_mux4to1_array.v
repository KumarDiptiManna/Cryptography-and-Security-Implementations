module mux4(data, sel, mux_out);
    input  [3:0] data;
    input  [1:0] sel;
    output       mux_out;
    reg arr [0:3];             // array of 4 elements, 1 bit each
    always @(data) begin
        arr[0] = data[0];
        arr[1] = data[1];
        arr[2] = data[2];
        arr[3] = data[3];
    end
    assign mux_out = arr[sel]; // pick element using sel
endmodule

module main();
    reg  [3:0] data;
    reg  [1:0] sel;
    wire       out1;
    integer i;

    mux4 m1(data, sel, out1);

    initial
    begin
        $monitor("data=%b sel=%b -> mux_out=%b", data, sel, out1);
        for (i = 0; i < 64; i = i + 1)   // all 16 data x 4 sel combinations
        begin
            {data, sel} = i;
            #5;
        end
    end
endmodule

//Developed with assistance from Claude (AI assistant by Anthropic)
